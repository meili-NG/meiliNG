package webui

import (
	"slices"
	"testing"
	"time"

	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

func TestPerProcessMagicTokenExpiresAndIsRevocable(t *testing.T) {
	cfg := newAdminTokenConfig()
	services := tokens.NewServices(cfg)
	t.Cleanup(func() { _ = RevokeSharedAdminToken(services) })

	token := ProvisionSharedAdminToken(cfg, services)
	if token == "" {
		t.Fatal("no magic token was provisioned")
	}
	if !slices.Equal(cfg.AdminConfig.AdminTokens, []string{"configured-token"}) {
		t.Fatalf("the configured admin tokens changed: %v", cfg.AdminConfig.AdminTokens)
	}
	if SharedAdminTokenValue(services) != token || AdminTokenKind(cfg, services, token) == "" {
		t.Fatal("the provisioned magic token is rejected")
	}

	localMagicToken.Lock()
	localMagicToken.expiresAt = time.Now().Add(-time.Second)
	localMagicToken.Unlock()
	if SharedAdminTokenValue(services) != "" || AdminTokenKind(cfg, services, token) != "" {
		t.Fatal("an expired magic token is accepted")
	}

	token = ProvisionSharedAdminToken(cfg, services)
	if AdminTokenKind(cfg, services, token) == "" {
		t.Fatal("a magic token provisioned after expiry is rejected")
	}
	if err := RevokeSharedAdminToken(services); err != nil {
		t.Fatalf("RevokeSharedAdminToken: %v", err)
	}
	if SharedAdminTokenValue(services) != "" || AdminTokenKind(cfg, services, token) != "" {
		t.Fatal("a revoked magic token is accepted")
	}
	if AdminTokenKind(cfg, services, "configured-token") == "" {
		t.Fatal("a configured admin token is rejected after the magic token was revoked")
	}
}
