package test

import (
	"net/http"
	"testing"
)

// The OAuth2/OIDC endpoints answer browsers of any origin; the rest of the API
// answers only server.frontendOrigins, matched by scheme, host and port.
func TestCORSAllowsFrontendOriginsOnTheManagementAPI(t *testing.T) {
	env := newFeatureEnv(t)
	// The first request through the test helper prepares the router.
	mustJSONRequest(t, env.server, http.MethodGet, "/health", nil, nil).Body.Close()

	allowed := func(path, origin string) string {
		t.Helper()
		resp := rawRequest(t, env, "OPTIONS", path, "Origin: "+origin, "Access-Control-Request-Method: POST", "Access-Control-Request-Headers: authorization")
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("OPTIONS %s from %s = %d, want 204", path, origin, resp.StatusCode)
		}
		return resp.Header.Get("Access-Control-Allow-Origin")
	}

	for _, path := range []string{"/v2/oauth2/token", "/v2/oauth2/userinfo/", "/v2/jwks", "/.well-known/openid-configuration"} {
		if got := allowed(path, "https://spa.example.net"); got != "*" {
			t.Errorf("%s from another origin: Access-Control-Allow-Origin = %q, want *", path, got)
		}
	}

	for _, path := range []string{"/v2/users/", "/v2/apps/", "/v2/oauth2/device/authorize"} {
		if got := allowed(path, "https://accounts.example.com"); got != "https://accounts.example.com" {
			t.Errorf("%s from the frontend origin: Access-Control-Allow-Origin = %q", path, got)
		}
		for _, origin := range []string{"https://spa.example.net", "http://accounts.example.com", "https://accounts.example.com:8443"} {
			if got := allowed(path, origin); got != "" {
				t.Errorf("%s from %s: Access-Control-Allow-Origin = %q, want none", path, origin, got)
			}
		}
	}
}
