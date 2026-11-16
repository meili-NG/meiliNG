package test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// logoutFixture is a signed-in user who authorized a client that takes
// back- and front-channel logout, and the ID token that authorization gave.
type logoutFixture struct {
	signedInFixture
	idToken     string
	backchannel chan string
}

func newLogoutFixture(t *testing.T, env *featureEnv) logoutFixture {
	t.Helper()
	f := logoutFixture{signedInFixture: newSignedInFixture(t, env), backchannel: make(chan string, 4)}

	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.backchannel <- r.PostForm.Get("logout_token")
	}))
	t.Cleanup(receiver.Close)

	settings := "/v2/apps/" + f.client.clientID.String() + "/oauth2/logout/"
	resp := mustJSONRequest(t, env.server, http.MethodPut, settings, map[string]any{
		"postLogoutRedirectUris": []string{"https://client.example.com/bye"},
		"backchannelLogoutUri":   receiver.URL + "/backchannel",
		"frontchannelLogoutUri":  "https://client.example.com/frontchannel",
	}, adminHeaders())
	if raw, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT logout settings = %d %s", resp.StatusCode, raw)
	}
	resp.Body.Close()

	resp = mustJSONRequest(t, env.server, http.MethodPost, f.query("&approve=true"), nil, bearerHeaders(f.session))
	var authorized struct {
		Code string `json:"code"`
	}
	decodeJSONBody(t, resp, &authorized)
	resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
		"client_id": {f.client.clientID.String()}, "client_secret": {f.client.secret},
		"code": {authorized.Code}, "grant_type": {"authorization_code"},
	}, nil)
	var issued issuedTokens
	decodeJSONBody(t, resp, &issued)
	f.idToken = issued.IDToken
	return f
}

// expectLogoutToken waits for the back-channel delivery and checks the token.
func (f logoutFixture) expectLogoutToken(t *testing.T, env *featureEnv) {
	t.Helper()
	select {
	case token := <-f.backchannel:
		var claims tokens.LogoutTokenClaims
		if err := env.app.TokenServices().JWT().ParseTokenCustomClaims(token, &claims); err != nil {
			t.Fatalf("logout token does not verify: %v", err)
		}
		if _, ok := claims.Events[tokens.BackchannelLogoutEvent]; !ok || claims.Subject != f.userID ||
			claims.SID != jwtClaims(t, f.session)["sid"] || !claims.Audience.Contains(f.client.clientID.String()) {
			t.Fatalf("logout token claims = %+v", claims)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no back-channel logout token arrived")
	}
}

func (f logoutFixture) sessionUsers(t *testing.T, env *featureEnv) []string {
	t.Helper()
	payload, err := env.app.TokenServices().Session().Get(f.session)
	if err != nil {
		t.Fatal(err)
	}
	return payload.Users
}

func TestRPInitiatedLogout(t *testing.T) {
	env := newFeatureEnv(t)
	f := newLogoutFixture(t, env)

	// The end_session_endpoint checks the request, then sends the browser to
	// the frontend to confirm.
	logout := "/v2/oauth2/logout?id_token_hint=" + url.QueryEscape(f.idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape("https://client.example.com/bye") + "&state=s1"
	resp := mustJSONRequest(t, env.server, http.MethodGet, logout, nil, nil)
	resp.Body.Close()
	location, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || location.Query().Get("end_session") != "1" || location.Query().Get("state") != "s1" {
		t.Fatalf("end session = %d, Location = %v", resp.StatusCode, location)
	}

	for _, bad := range []string{
		"/v2/oauth2/logout?id_token_hint=" + url.QueryEscape(f.idToken) + "&post_logout_redirect_uri=" + url.QueryEscape("https://evil.example.com/"),
		"/v2/oauth2/logout?post_logout_redirect_uri=" + url.QueryEscape("https://client.example.com/bye"),
		"/v2/oauth2/logout?id_token_hint=not-a-token",
	} {
		resp := mustJSONRequest(t, env.server, http.MethodGet, bad, nil, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", bad, resp.StatusCode)
		}
	}

	// An admin credential has no session to end.
	confirm := map[string]any{"idTokenHint": f.idToken, "postLogoutRedirectUri": "https://client.example.com/bye", "state": "s1"}
	resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/oauth2/logout/confirm", confirm, adminHeaders())
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin confirming a logout = %d, want 403", resp.StatusCode)
	}

	resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/oauth2/logout/confirm", confirm, bearerHeaders(f.session))
	var result struct {
		RedirectURI            string   `json:"redirectUri"`
		FrontchannelLogoutURIs []string `json:"frontchannelLogoutUris"`
	}
	decodeJSONBody(t, resp, &result)
	if resp.StatusCode != http.StatusOK || result.RedirectURI != "https://client.example.com/bye?state=s1" {
		t.Fatalf("confirm = %d %+v", resp.StatusCode, result)
	}
	if len(result.FrontchannelLogoutURIs) != 1 || !strings.HasPrefix(result.FrontchannelLogoutURIs[0], "https://client.example.com/frontchannel?") ||
		!strings.Contains(result.FrontchannelLogoutURIs[0], "sid=") {
		t.Fatalf("front-channel URIs = %v", result.FrontchannelLogoutURIs)
	}
	f.expectLogoutToken(t, env)
	if users := f.sessionUsers(t, env); len(users) != 0 {
		t.Fatalf("session users after logout = %v", users)
	}
}

// Signing out of meiliNG itself tells the applications the same way.
func TestSignOutTellsApplications(t *testing.T) {
	env := newFeatureEnv(t)
	f := newLogoutFixture(t, env)

	resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signout", nil, bearerHeaders(f.session))
	var result struct {
		FrontchannelLogoutURIs []string `json:"frontchannelLogoutUris"`
	}
	decodeJSONBody(t, resp, &result)
	if resp.StatusCode != http.StatusOK || len(result.FrontchannelLogoutURIs) != 1 {
		t.Fatalf("sign out = %d %+v", resp.StatusCode, result)
	}
	f.expectLogoutToken(t, env)

	resp = mustJSONRequest(t, env.server, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	var discovery map[string]any
	decodeJSONBody(t, resp, &discovery)
	if !strings.HasSuffix(discovery["end_session_endpoint"].(string), "/v2/oauth2/logout") ||
		discovery["backchannel_logout_supported"] != true || discovery["frontchannel_logout_supported"] != true {
		t.Fatalf("discovery = %v", discovery)
	}
}
