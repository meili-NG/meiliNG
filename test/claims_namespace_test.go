package test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// TestClaimsNamespaceEndToEnd proves token.jwt.claimsNamespace reaches the wire:
// discovery advertises it, issued session tokens carry private claims under
// it, and the server still accepts those tokens.
func TestClaimsNamespaceEndToEnd(t *testing.T) {
	const ns = "https://claims.example.com/v2/"
	env := newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) {
		cfg.TokenConfig.JWT.ClaimsNamespace = ns
	})

	resp := mustJSONRequest(t, env.server, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	var discovery struct {
		ClaimsNamespace string `json:"meiling_claims_namespace"`
	}
	decodeJSONBody(t, resp, &discovery)
	if discovery.ClaimsNamespace != ns {
		t.Fatalf("discovery meiling_claims_namespace = %q, want %q", discovery.ClaimsNamespace, ns)
	}

	token := mustCreateSessionToken(t, env)
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatalf("decode session token: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal session token: %v", err)
	}
	if payload[ns+"token_type"] != tokens.TokenTypeSession {
		t.Fatalf("session token payload = %s, want token_type under %q", raw, ns)
	}

	resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/", nil, bearerHeaders(token))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v2/sessions/ with namespaced token = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}
