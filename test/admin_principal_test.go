package test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// The admin probe names the calling credential without revealing it, and a
// user session is never an admin.
func TestAdminProbeNamesTheCredential(t *testing.T) {
	env := newFeatureEnv(t)

	resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/admin/", nil, adminHeaders())
	var probe struct {
		Admin bool   `json:"admin"`
		Kind  string `json:"kind"`
		Actor string `json:"actor"`
	}
	decodeJSONBody(t, resp, &probe)
	if resp.StatusCode != http.StatusOK || !probe.Admin || probe.Kind != "admin_token" ||
		!strings.HasPrefix(probe.Actor, "admin_token:") || len(probe.Actor) != len("admin_token:")+8 {
		t.Fatalf("admin probe = %d %+v", resp.StatusCode, probe)
	}
	if strings.Contains(probe.Actor, "test-admin-token") {
		t.Fatalf("the actor reveals the token: %q", probe.Actor)
	}

	session := mustCreateSessionToken(t, env)
	resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/admin/", nil, bearerHeaders(session))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a user session passed the admin probe")
	}
}

// admin.accept decides which admin credentials count; a listed token of a
// kind left out is no admin.
func TestAdminAcceptList(t *testing.T) {
	env := newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) {
		cfg.AdminConfig.Accept = []string{config.AdminAcceptBootstrap}
	})
	resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/admin/", nil, adminHeaders())
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("an admin.adminTokens token was admin without token in admin.accept")
	}

	cfg := &config.MeilingConfig{}
	cfg.AdminConfig.Accept = []string{"tokens"}
	if err := cfg.AdminConfig.Validate(); err == nil {
		t.Fatal("an unknown admin.accept kind was accepted")
	}
}
