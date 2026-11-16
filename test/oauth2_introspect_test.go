package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/auth"
)

type issuedTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// mustIssueTokens runs the authorization code flow for f's user and client and
// returns the tokens, an ID token included.
func mustIssueTokens(t *testing.T, env *featureEnv, f implicitFixture) issuedTokens {
	t.Helper()
	resp := f.authorize(t, env, "code", "offline")
	var authorized struct {
		Code string `json:"code"`
	}
	decodeJSONBody(t, resp, &authorized)
	if authorized.Code == "" {
		t.Fatalf("authorize = %d without a code", resp.StatusCode)
	}

	resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
		"client_id":     {f.client.clientID.String()},
		"client_secret": {f.client.secret},
		"code":          {authorized.Code},
		"grant_type":    {"authorization_code"},
	}, nil)
	var issued issuedTokens
	decodeJSONBody(t, resp, &issued)
	if issued.AccessToken == "" || issued.RefreshToken == "" || issued.IDToken == "" {
		t.Fatalf("token exchange = %d %+v, want access, refresh and ID tokens", resp.StatusCode, issued)
	}
	return issued
}

func TestTokenInfoOfAnIDToken(t *testing.T) {
	env := newFeatureEnv(t)
	f := newImplicitFixture(t, env)
	issued := mustIssueTokens(t, env, f)

	resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?id_token="+url.QueryEscape(issued.IDToken), nil, nil)
	var info struct {
		Sub       string   `json:"sub"`
		Aud       []string `json:"aud"`
		Scope     string   `json:"scope"`
		ExpiresIn int      `json:"expires_in"`
	}
	decodeJSONBody(t, resp, &info)
	if resp.StatusCode != http.StatusOK || info.Sub != f.userID || len(info.Aud) != 1 || info.Aud[0] != f.client.clientID.String() || info.ExpiresIn <= 0 {
		t.Fatalf("tokeninfo of an ID token = %d %+v", resp.StatusCode, info)
	}

	// An access token is not an ID token, and garbage is nothing.
	for _, token := range []string{issued.AccessToken, "not-a-token"} {
		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?id_token="+url.QueryEscape(token), nil, nil)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("tokeninfo accepted %q as an ID token", token[:min(len(token), 12)])
		}
	}
}

func TestTokenIntrospection(t *testing.T) {
	env := newFeatureEnv(t)
	f := newImplicitFixture(t, env)
	issued := mustIssueTokens(t, env, f)

	introspect := func(client oauthClientSeed, token, hint string) (int, map[string]any) {
		t.Helper()
		form := url.Values{"token": {token}, "client_id": {client.clientID.String()}, "client_secret": {client.secret}}
		if hint != "" {
			form.Set("token_type_hint", hint)
		}
		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/introspect", form, nil)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var body map[string]any
		json.Unmarshal(raw, &body)
		return resp.StatusCode, body
	}

	status, body := introspect(f.client, issued.AccessToken, "")
	if status != http.StatusOK || body["active"] != true || body["sub"] != f.userID ||
		body["client_id"] != f.client.clientID.String() || body["token_type"] != "access_token" || !strings.Contains(body["scope"].(string), "openid") {
		t.Fatalf("introspecting the client's own access token = %d %v", status, body)
	}
	if status, body := introspect(f.client, issued.RefreshToken, "refresh_token"); status != http.StatusOK || body["active"] != true || body["token_type"] != "refresh_token" {
		t.Fatalf("introspecting the client's own refresh token = %d %v", status, body)
	}

	// Another confidential client learns nothing about the token, not even that it exists.
	other := seedOAuthClient(t, env, false, true)
	if status, body := introspect(other, issued.AccessToken, ""); status != http.StatusOK || len(body) != 1 || body["active"] != false {
		t.Fatalf("another client introspecting = %d %v, want only active: false", status, body)
	}
	// A client policy can let a client see every token.
	t.Cleanup(auth.Clients.Reset)
	auth.Clients.Override(auth.ClientPolicy{
		BypassConsent: auth.Clients.Default().BypassConsent,
		IntrospectAny: func(_ context.Context, c auth.Client) bool { return c.ApplicationID == other.clientID },
	})
	if status, body := introspect(other, issued.AccessToken, ""); status != http.StatusOK || body["active"] != true {
		t.Fatalf("a client the policy trusts introspecting = %d %v", status, body)
	}

	// A public client cannot introspect, and a wrong secret is refused.
	public := seedOAuthClient(t, env, false, false)
	if status, _ := introspect(public, issued.AccessToken, ""); status < 400 {
		t.Fatalf("a public client introspecting = %d, want an error", status)
	}
	wrong := f.client
	wrong.secret = "wrong"
	if status, _ := introspect(wrong, issued.AccessToken, ""); status < 400 {
		t.Fatalf("introspecting with a wrong secret = %d, want an error", status)
	}

	// A revoked token is inactive.
	mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{"token": {issued.AccessToken}}, nil).Body.Close()
	if status, body := introspect(f.client, issued.AccessToken, ""); status != http.StatusOK || body["active"] != false {
		t.Fatalf("introspecting a revoked token = %d %v", status, body)
	}

	resp := mustJSONRequest(t, env.server, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	var discovery map[string]any
	decodeJSONBody(t, resp, &discovery)
	if !strings.HasSuffix(discovery["introspection_endpoint"].(string), "/v2/oauth2/introspect") ||
		!strings.HasSuffix(discovery["revocation_endpoint"].(string), "/v2/oauth2/revoke") {
		t.Fatalf("discovery = %v", discovery)
	}
}
