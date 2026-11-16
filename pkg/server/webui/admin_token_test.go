package webui

import (
	"slices"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

func newAdminTokenConfig(valkeyAddresses ...string) *config.MeilingConfig {
	cfg := &config.MeilingConfig{}
	cfg.WebUIConfig.Enable = true
	cfg.WebUIConfig.ProvideAdminURL = true
	cfg.AdminConfig.AdminTokens = []string{"configured-token"}
	cfg.AdminConfig.Accept = []string{config.AdminAcceptToken, config.AdminAcceptBootstrap}
	cfg.ValkeyConfig.InitAddress = valkeyAddresses
	return cfg
}

func TestAdminTokenKindAcceptsOnlyKnownTokens(t *testing.T) {
	cfg := newAdminTokenConfig()
	services := tokens.NewServices(cfg)

	if AdminTokenKind(cfg, services, "configured-token") == "" {
		t.Fatal("a configured admin token is rejected")
	}
	for _, token := range []string{"", "unknown-token"} {
		if AdminTokenKind(cfg, services, token) != "" {
			t.Fatalf("token %q is accepted", token)
		}
	}
	if AdminTokenKind(nil, services, "configured-token") != "" {
		t.Fatal("a token is accepted without a configuration")
	}
}

func TestPerProcessMagicTokenIsAccepted(t *testing.T) {
	cfg := newAdminTokenConfig()
	services := tokens.NewServices(cfg)

	token := ProvisionSharedAdminToken(cfg, services)
	if token == "" {
		t.Fatal("no magic token was provisioned")
	}
	if AdminTokenKind(cfg, services, token) == "" {
		t.Fatal("the provisioned magic token is rejected")
	}
}

// With a shared store configured the magic token lives only there, so a store
// that does not hold it (here: one that cannot be reached) accepts nothing but
// the configured tokens.
func TestMagicTokenIsHeldOnlyInTheSharedStore(t *testing.T) {
	cfg := newAdminTokenConfig("127.0.0.1:1")
	services := tokens.NewServices(cfg)

	if token := ProvisionSharedAdminToken(cfg, services); token != "" {
		t.Fatalf("a magic token was provisioned without the shared store: %q", token)
	}
	if !slices.Equal(cfg.AdminConfig.AdminTokens, []string{"configured-token"}) {
		t.Fatalf("the configured admin tokens changed: %v", cfg.AdminConfig.AdminTokens)
	}
	if AdminTokenKind(cfg, services, "magic-token") != "" {
		t.Fatal("a token the shared store does not confirm is accepted")
	}
	if AdminTokenKind(cfg, services, "configured-token") == "" {
		t.Fatal("a configured admin token is rejected while the shared store is down")
	}
}
