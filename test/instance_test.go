package test

import (
	"net/http"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// TestInstanceDescribesBranding proves a user interface can read the
// configured identity from GET /v2/instance.
func TestInstanceDescribesBranding(t *testing.T) {
	env := newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) {
		cfg.InstanceConfig.Name = "Acme ID"
		cfg.InstanceConfig.LogoURL = "https://acme.example/logo.svg"
		cfg.InstanceConfig.SupportURL = "https://acme.example/help"
		cfg.InstanceConfig.Description = "Acme's sign-in"
	})

	resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/instance", nil, nil)
	var info map[string]any
	decodeJSONBody(t, resp, &info)
	want := map[string]string{
		"name":        "Acme ID",
		"description": "Acme's sign-in",
		"logoUrl":     "https://acme.example/logo.svg",
		"supportUrl":  "https://acme.example/help",
	}
	for key, value := range want {
		if info[key] != value {
			t.Fatalf("/v2/instance %s = %v, want %q (body %v)", key, info[key], value, info)
		}
	}
}
