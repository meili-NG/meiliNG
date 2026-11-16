package test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

func TestOAuth2AuthorizeEnforcement(t *testing.T) {
	env := newFeatureEnv(t)

	username := "authorize" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "authorize-password-123", username+"@example.com")
	sessionToken := mustCreateSessionToken(t, env)
	mustAttachUserToSession(t, env, sessionToken, userID)

	authPath := func(client oauthClientSeed, scope string, extra string) string {
		return fmt.Sprintf("/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s%s",
			client.clientID.String(),
			url.QueryEscape(scope),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(userID),
			extra,
		)
	}

	authorize := func(client oauthClientSeed, scope string, extra string) *http.Response {
		return mustJSONRequest(t, env.server, http.MethodPost, authPath(client, scope, extra), nil, bearerHeaders(sessionToken))
	}

	expectError := func(t *testing.T, resp *http.Response, status int, errType string) {
		t.Helper()

		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != status {
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, status, string(raw))
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode error body %s: %v", string(raw), err)
		}
		got := body["type"]
		if got == nil {
			got = body["error"]
		}
		if got != errType {
			t.Fatalf("error = %v, want %q, body=%s", got, errType, string(raw))
		}
	}

	mustCode := func(t *testing.T, client oauthClientSeed, scope string, extra string) string {
		t.Helper()

		resp := authorize(client, scope, extra)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("authorize %q status = %d, want %d, body=%s", scope, resp.StatusCode, http.StatusOK, string(raw))
		}
		var body struct {
			Code string `json:"code"`
		}
		decodeJSONBody(t, resp, &body)
		if body.Code == "" {
			t.Fatalf("authorize %q returned no code", scope)
		}
		return body.Code
	}

	exchange := func(client oauthClientSeed, code string, verifier string) *http.Response {
		values := url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"code":          {code},
			"grant_type":    {"authorization_code"},
		}
		if verifier != "" {
			values.Set("code_verifier", verifier)
		}
		return mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", values, nil)
	}

	type tokenBody struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}

	mustExchange := func(t *testing.T, client oauthClientSeed, code string, verifier string) tokenBody {
		t.Helper()

		resp := exchange(client, code, verifier)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("code exchange status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var body tokenBody
		decodeJSONBody(t, resp, &body)
		return body
	}

	userInfo := func(accessToken string) *http.Response {
		return mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/userinfo", nil, bearerHeaders(accessToken))
	}

	ensurePermissionScope(t, env, "openid")
	ensurePermissionScope(t, env, "profile")

	t.Run("a scope that names no permission is rejected", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)

		for _, scope := range []string{" ", "\t", "  \n "} {
			resp := mustJSONRequest(t, env.server, http.MethodGet, authPath(client, scope, ""), nil, bearerHeaders(sessionToken))
			expectError(t, resp, http.StatusBadRequest, "invalid_request")

			expectError(t, authorize(client, scope, "&approve=true"), http.StatusBadRequest, "invalid_request")

			resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/device", url.Values{
				"client_id":     {client.clientID.String()},
				"client_secret": {client.secret},
				"scope":         {scope},
			}, nil)
			expectError(t, resp, http.StatusBadRequest, "invalid_request")
		}
	})

	t.Run("a code is issued only with consent on record or an explicit approval", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)

		expectError(t, authorize(client, "openid", ""), http.StatusForbidden, "consent_required")
		expectError(t, authorize(client, "openid", "&approve=false"), http.StatusForbidden, "consent_required")
		expectError(t, authorize(client, "openid", "&prompt=none"), http.StatusForbidden, "consent_required")
		expectError(t, authorize(client, "openid", "&prompt=none&approve=true"), http.StatusForbidden, "consent_required")

		// Redeeming an approved code records the consent.
		mustExchange(t, client, mustCode(t, client, "openid", "&approve=true"), "")

		mustCode(t, client, "openid", "")
		mustCode(t, client, "openid", "&prompt=none")

		expectError(t, authorize(client, "openid", "&prompt=consent"), http.StatusForbidden, "consent_required")
		mustCode(t, client, "openid", "&prompt=consent&approve=true")

		// A permission the earlier grant does not cover is pending again.
		expectError(t, authorize(client, "openid profile", ""), http.StatusForbidden, "consent_required")
		expectError(t, authorize(client, "openid profile", "&prompt=none"), http.StatusForbidden, "consent_required")
	})

	t.Run("prompt is a space-delimited list", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		mustExchange(t, client, mustCode(t, client, "openid", "&approve=true"), "")

		consent := func(extra string) *http.Response {
			return mustJSONRequest(t, env.server, http.MethodGet, authPath(client, "openid", extra), nil, bearerHeaders(sessionToken))
		}

		mustCode(t, client, "openid", "&prompt=login")

		for _, prompt := range []string{"select_account consent", "login consent", "login select_account"} {
			extra := "&prompt=" + url.QueryEscape(prompt)

			resp := consent(extra)
			if resp.StatusCode != http.StatusOK {
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				t.Fatalf("consent check with prompt %q status = %d, body=%s", prompt, resp.StatusCode, string(raw))
			}
			var info struct {
				UserConsentRequired bool `json:"userConsentRequired"`
			}
			decodeJSONBody(t, resp, &info)
			if !info.UserConsentRequired {
				t.Fatalf("prompt %q does not force consent", prompt)
			}

			expectError(t, authorize(client, "openid", extra), http.StatusForbidden, "consent_required")
			mustCode(t, client, "openid", extra+"&approve=true")
		}

		for _, prompt := range []string{"none login", "consent none", "login unknown"} {
			extra := "&prompt=" + url.QueryEscape(prompt)

			expectError(t, consent(extra), http.StatusBadRequest, "invalid_request")
			expectError(t, authorize(client, "openid", extra+"&approve=true"), http.StatusBadRequest, "invalid_request")
		}
	})

	t.Run("the authorization endpoint carries include_granted_scopes to the frontend", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		request := url.Values{
			"client_id":     {client.clientID.String()},
			"redirect_uri":  {client.redirectURI},
			"response_type": {"code"},
			"scope":         {"openid"},
		}

		carried := func(t *testing.T, resp *http.Response) string {
			t.Helper()

			resp.Body.Close()
			if resp.StatusCode != http.StatusTemporaryRedirect {
				t.Fatalf("auth redirect status = %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
			}
			location, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			return location.Query().Get("include_granted_scopes")
		}

		if got := carried(t, mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/auth?"+request.Encode(), nil, nil)); got != "" {
			t.Fatalf("GET without include_granted_scopes carried %q", got)
		}
		if got := carried(t, mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/auth", request, nil)); got != "" {
			t.Fatalf("POST without include_granted_scopes carried %q", got)
		}

		for value, want := range map[string]string{"false": "", "False": "", "0": "", "true": "true", "True": "true", "1": "true"} {
			request.Set("include_granted_scopes", value)

			if got := carried(t, mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/auth?"+request.Encode(), nil, nil)); got != want {
				t.Fatalf("GET with include_granted_scopes=%q carried %q, want %q", value, got, want)
			}
			if got := carried(t, mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/auth", request, nil)); got != want {
				t.Fatalf("POST with include_granted_scopes=%q carried %q, want %q", value, got, want)
			}
		}

		// The form accepts a value that is empty or not a boolean, and reads it as false.
		for _, value := range []string{"", "yes"} {
			request.Set("include_granted_scopes", value)
			if got := carried(t, mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/auth", request, nil)); got != "" {
				t.Fatalf("POST with include_granted_scopes=%q carried %q, want nothing", value, got)
			}
		}
	})

	t.Run("profile claims need the profile permission", func(t *testing.T) {
		profileClaims := []string{"name", "given_name", "family_name", "preferred_username"}

		resp := mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/userdata", map[string]any{
			"firstName": "Given",
			"lastName":  "Family",
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("update userdata status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		client := seedOAuthClient(t, env, true, true)
		granted := mustExchange(t, client, mustCode(t, client, "openid", "&approve=true"), "")

		var idToken tokens.IDTokenContent
		if err := env.app.TokenServices().JWT().ParseTokenCustomClaims(granted.IDToken, &idToken); err != nil {
			t.Fatalf("parse id token: %v", err)
		}
		if idToken.Subject != userID {
			t.Fatalf("id token sub = %q, want %q", idToken.Subject, userID)
		}
		if idToken.Name != "" || idToken.GivenName != "" || idToken.FamilyName != "" || idToken.PreferredUsername != "" {
			t.Fatalf("id token without profile carries profile claims: %+v", idToken.IDTokenPayload)
		}

		resp = userInfo(granted.AccessToken)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("userinfo status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var claims map[string]any
		decodeJSONBody(t, resp, &claims)
		if claims["sub"] != userID {
			t.Fatalf("userinfo sub = %v, want %q", claims["sub"], userID)
		}
		for _, claim := range profileClaims {
			if _, ok := claims[claim]; ok {
				t.Fatalf("userinfo without profile carries %q: %v", claim, claims)
			}
		}

		client = seedOAuthClient(t, env, true, true)
		granted = mustExchange(t, client, mustCode(t, client, "openid profile", "&approve=true"), "")
		resp = userInfo(granted.AccessToken)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("userinfo with profile status = %d, body=%s", resp.StatusCode, string(raw))
		}
		decodeJSONBody(t, resp, &claims)
		if claims["preferred_username"] != username || claims["given_name"] != "Given" || claims["family_name"] != "Family" || claims["name"] == nil {
			t.Fatalf("userinfo with profile = %v, want the profile claims", claims)
		}
	})

	t.Run("userinfo needs the openid permission", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		granted := mustExchange(t, client, mustCode(t, client, "profile", "&approve=true"), "")

		expectError(t, userInfo(granted.AccessToken), http.StatusForbidden, "insufficient_scope")
	})

	t.Run("a code challenge without a method is a plain challenge", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

		code := mustCode(t, client, "openid", "&approve=true&code_challenge="+verifier)
		expectError(t, exchange(client, code, ""), http.StatusBadRequest, "invalid_grant")
		expectError(t, exchange(client, code, verifier+"x"), http.StatusBadRequest, "invalid_grant")
		mustExchange(t, client, code, verifier)
	})

	t.Run("a code verifier is refused for a code issued without a challenge", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)

		code := mustCode(t, client, "openid", "&approve=true")
		expectError(t, exchange(client, code, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), http.StatusBadRequest, "invalid_grant")
		mustExchange(t, client, code, "")
	})

	t.Run("only an admin lists every client", func(t *testing.T) {
		foreign := seedOAuthClient(t, env, true, true)

		listed := func(headers map[string]string) bool {
			resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/apps/?page=1&size=100&all=true", nil, headers)
			if resp.StatusCode != http.StatusOK {
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				t.Fatalf("list clients status = %d, body=%s", resp.StatusCode, string(raw))
			}
			var body struct {
				Data []struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			decodeJSONBody(t, resp, &body)
			for _, client := range body.Data {
				if client.ID == foreign.clientID.String() {
					return true
				}
			}
			return false
		}

		if listed(bearerHeaders(sessionToken)) {
			t.Fatalf("a user who never authorized the client sees it with all=true")
		}
		if !listed(adminHeaders()) {
			t.Fatalf("an admin does not see the client with all=true")
		}
	})
}
