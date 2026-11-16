package test

import (
	"io"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/server/webui"
)

func TestPerProcessMagicAdminTokenIsRevocable(t *testing.T) {
	t.Run("beside configured admin tokens", func(t *testing.T) {
		testPerProcessMagicAdminToken(t, newFeatureEnv(t))
	})
	t.Run("without configured admin tokens", func(t *testing.T) {
		testPerProcessMagicAdminToken(t, newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) {
			cfg.AdminConfig.AdminTokens = nil
		}))
	})
}

func testPerProcessMagicAdminToken(t *testing.T, env *featureEnv) {
	cfg := env.app.Config()
	cfg.WebUIConfig.Enable = true
	cfg.WebUIConfig.ProvideAdminURL = true
	services := env.app.TokenServices()

	magic := webui.ProvisionSharedAdminToken(cfg, services)
	if magic == "" {
		t.Fatal("no magic admin token was provisioned")
	}
	if slices.Contains(cfg.AdminConfig.AdminTokens, magic) {
		t.Fatal("the magic admin token was added to the configured admin tokens")
	}
	authorization := "Meiling-Admin-Token " + magic

	// One route behind the admin check, one behind the session check.
	paths := []string{"/v2/oauth2/audiences/", "/v2/users/?page=1&size=1&all=true"}
	status := func(path string) int {
		resp := mustJSONRequest(t, env.server, http.MethodGet, path, nil, map[string]string{"Authorization": authorization})
		resp.Body.Close()
		return resp.StatusCode
	}

	for _, path := range paths {
		if got := status(path); got != http.StatusOK {
			t.Fatalf("GET %s with the magic token = %d, want %d", path, got, http.StatusOK)
		}
	}
	if _, err := api.ParseAuthorization(cfg, services, authorization); err != nil {
		t.Fatalf("ParseAuthorization with the magic token: %v", err)
	}

	resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{"token": {magic}}, nil)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("revoke status = %d, body=%s", resp.StatusCode, string(raw))
	}
	resp.Body.Close()

	for _, path := range paths {
		if got := status(path); got != http.StatusUnauthorized {
			t.Fatalf("GET %s with the revoked magic token = %d, want %d", path, got, http.StatusUnauthorized)
		}
	}
	if _, err := api.ParseAuthorization(cfg, services, authorization); err == nil {
		t.Fatal("ParseAuthorization accepts the revoked magic token")
	}
}
