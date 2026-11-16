package webui

import (
	"log"
	"slices"
	"sync"
	"time"

	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// MagicAdminTokenKey is the shared Valkey key replicas coordinate on so the
// whole cluster agrees on a single webui.provideAdminUrl magic token.
var MagicAdminTokenKey = ext.NewSlot("meiling:webui:admin-magic-token")

// magicAdminTokenTTL bounds how long a provisioned magic token stays valid:
// long enough to survive a rolling restart, short enough that a leaked link
// stops working on its own.
const magicAdminTokenTTL = 24 * time.Hour

// localMagicToken is the magic token of an instance that has no shared store.
var localMagicToken struct {
	sync.Mutex
	value     string
	expiresAt time.Time
}

// localMagicTokenValue returns the per-process magic token, or "" once it has
// expired or been revoked.
func localMagicTokenValue() string {
	localMagicToken.Lock()
	defer localMagicToken.Unlock()
	if !time.Now().Before(localMagicToken.expiresAt) {
		localMagicToken.value = ""
	}
	return localMagicToken.value
}

// ProvisionSharedAdminToken elects the magic admin token for this instance.
//
// With Valkey configured, replicas coordinate via SET NX so they converge on a
// single token (with a TTL). The elected value is held only in the shared
// store, so deleting the key or letting it expire ends the token on every
// replica. Without Valkey it is a per-process random token with the same TTL,
// held apart from the configured admin tokens (single-instance mode).
//
// Returns the token, or "" when provisioning does not apply or the shared
// store cannot be reached.
func ProvisionSharedAdminToken(cfg *config.MeilingConfig, services *tokens.Services) string {
	if cfg == nil || !cfg.WebUIConfig.Enable || !cfg.WebUIConfig.ProvideAdminURL {
		return ""
	}

	candidate := utils.RandomString(adminTokenLength)

	if global := sharedStore(services); global != nil {
		elected, err := global.AcquireSharedString(
			MagicAdminTokenKey.Get(),
			candidate,
			magicAdminTokenTTL,
		)
		if err != nil {
			// No per-process token here: it could not be revoked through the shared store.
			log.Printf("webui: admin sign-in link not provisioned: %v", err)
			return ""
		}
		return elected
	}

	localMagicToken.Lock()
	defer localMagicToken.Unlock()
	if localMagicToken.value == "" || !time.Now().Before(localMagicToken.expiresAt) {
		localMagicToken.value = candidate
		localMagicToken.expiresAt = time.Now().Add(magicAdminTokenTTL)
	}
	return localMagicToken.value
}

// AdminTokenKind returns which admin.accept kind token is, config.AdminAcceptToken
// or config.AdminAcceptBootstrap, or "" when it is not an admin token or its
// kind is not accepted. Every path that accepts an admin token decides through
// it, so a revoked or expired magic token is rejected on all of them. An
// unreachable store rejects the magic token.
func AdminTokenKind(cfg *config.MeilingConfig, services *tokens.Services, token string) string {
	if cfg == nil || token == "" {
		return ""
	}
	if cfg.AdminConfig.Accepts(config.AdminAcceptToken) && slices.Contains(cfg.AdminConfig.AdminTokens, token) {
		return config.AdminAcceptToken
	}
	if cfg.AdminConfig.Accepts(config.AdminAcceptBootstrap) && cfg.WebUIConfig.Enable && cfg.WebUIConfig.ProvideAdminURL && SharedAdminTokenValue(services) == token {
		return config.AdminAcceptBootstrap
	}
	return ""
}

// AdminPrincipal returns the principal of an admin token, or nil when token
// is not one AdminTokenKind accepts.
func AdminPrincipal(cfg *config.MeilingConfig, services *tokens.Services, token string) *tokens.Principal {
	switch AdminTokenKind(cfg, services, token) {
	case config.AdminAcceptToken:
		return &tokens.Principal{Kind: tokens.PrincipalAdminToken, ActorID: tokens.ActorID("admin_token", token)}
	case config.AdminAcceptBootstrap:
		return &tokens.Principal{Kind: tokens.PrincipalAdminToken, ActorID: tokens.ActorID("bootstrap", token)}
	}
	return nil
}

// sharedStore returns the store replicas coordinate on, or nil without Valkey.
func sharedStore(services *tokens.Services) *tokens.GlobalTokenManager {
	if services == nil {
		return nil
	}
	if global := services.Global(); global != nil && global.IsValkeyEnabled() {
		return global
	}
	return nil
}

// RevokeSharedAdminToken ends the magic token: it deletes the shared one so
// every replica stops accepting it, or clears the per-process one.
func RevokeSharedAdminToken(services *tokens.Services) error {
	global := sharedStore(services)
	if global == nil {
		localMagicToken.Lock()
		defer localMagicToken.Unlock()
		localMagicToken.value = ""
		return nil
	}
	return global.DeleteSharedKey(MagicAdminTokenKey.Get())
}

// SharedAdminTokenValue returns the current magic token, or "" if
// none/unavailable. Lets callers recognize a presented token as the magic one.
func SharedAdminTokenValue(services *tokens.Services) string {
	global := sharedStore(services)
	if global == nil {
		return localMagicTokenValue()
	}
	value, err := global.GetSharedString(MagicAdminTokenKey.Get())
	if err != nil {
		return ""
	}
	return value
}
