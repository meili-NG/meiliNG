package test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// jwtClaims decodes a JWT's payload without verifying it.
func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// signedInFixture is a user who signed into a session with their password,
// and a client to authorize.
type signedInFixture struct {
	client  oauthClientSeed
	userID  string
	session string
}

func newSignedInFixture(t *testing.T, env *featureEnv) signedInFixture {
	t.Helper()
	username := "oidc" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "oidc-password-123", username+"@example.com")
	session := mustCreateSessionToken(t, env)
	mustCompletePasswordSignIn(t, env, session, username, "oidc-password-123", nil)
	ensurePermissionScope(t, env, "openid")
	return signedInFixture{client: seedOAuthClient(t, env, true, true), userID: userID, session: session}
}

func (f signedInFixture) query(extra string) string {
	return fmt.Sprintf("/v2/apps/%s/oauth2/auth/?response_type=code&scope=openid&redirect_uri=%s&user_id=%s&nonce=n%s",
		f.client.clientID, url.QueryEscape(f.client.redirectURI), f.userID, extra)
}

func TestIDTokenCarriesHowTheUserSignedIn(t *testing.T) {
	env := newFeatureEnv(t)
	f := newSignedInFixture(t, env)

	resp := mustJSONRequest(t, env.server, http.MethodPost, f.query("&approve=true&max_age=3600&acr_values=1fa"), nil, bearerHeaders(f.session))
	var authorized struct {
		Code string `json:"code"`
	}
	decodeJSONBody(t, resp, &authorized)
	if authorized.Code == "" {
		t.Fatalf("authorize = %d without a code", resp.StatusCode)
	}
	resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
		"client_id": {f.client.clientID.String()}, "client_secret": {f.client.secret},
		"code": {authorized.Code}, "grant_type": {"authorization_code"},
	}, nil)
	var issued issuedTokens
	decodeJSONBody(t, resp, &issued)

	claims := jwtClaims(t, issued.IDToken)
	sid := jwtClaims(t, f.session)["sid"]
	authTime, _ := claims["auth_time"].(float64)
	amr, _ := claims["amr"].([]any)
	if claims["sid"] != sid || sid == nil {
		t.Fatalf("sid = %v, want the session's %v", claims["sid"], sid)
	}
	if time.Since(time.Unix(int64(authTime), 0)) > time.Minute {
		t.Fatalf("auth_time = %v, want the sign-in just now", authTime)
	}
	if len(amr) != 1 || amr[0] != "pwd" || claims["acr"] != "1fa" {
		t.Fatalf("amr = %v, acr = %v; want [pwd] and 1fa", amr, claims["acr"])
	}
}

func TestStrongerOrFresherSignInIsRequired(t *testing.T) {
	env := newFeatureEnv(t)
	f := newSignedInFixture(t, env)

	// A password-only sign-in does not meet acr_values=2fa.
	resp := mustJSONRequest(t, env.server, http.MethodGet, f.query("&acr_values=2fa"), nil, bearerHeaders(f.session))
	var consent struct {
		ReauthenticationRequired bool `json:"reauthenticationRequired"`
	}
	decodeJSONBody(t, resp, &consent)
	if !consent.ReauthenticationRequired {
		t.Fatal("the consent check did not ask for a stronger sign-in")
	}
	resp = mustJSONRequest(t, env.server, http.MethodPost, f.query("&acr_values=2fa&approve=true"), nil, bearerHeaders(f.session))
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "login_required") {
		t.Fatalf("authorize with acr_values=2fa = %d %s, want login_required", resp.StatusCode, raw)
	}

	// A user put into a session without signing in has no sign-in to measure.
	attached := newImplicitFixture(t, env)
	q := fmt.Sprintf("/v2/apps/%s/oauth2/auth/?response_type=code&scope=openid&redirect_uri=%s&user_id=%s&approve=true&max_age=600",
		attached.client.clientID, url.QueryEscape(attached.client.redirectURI), attached.userID)
	resp = mustJSONRequest(t, env.server, http.MethodPost, q, nil, bearerHeaders(attached.sessionToken))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("authorize with max_age and no sign-in record = %d, want 403", resp.StatusCode)
	}

	resp = mustJSONRequest(t, env.server, http.MethodGet, f.query("&max_age=-1"), nil, bearerHeaders(f.session))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a negative max_age = %d, want 400", resp.StatusCode)
	}
}
