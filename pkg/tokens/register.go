package tokens

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// ===== AUTHORIZATION =====

type ResourceRegisterContent struct {
	GlobalTokenPayload

	TOTP         string           `json:"totp"`
	WebAuthnData *WebAuthnContent `json:"webauthn"`
}

type WebAuthnContent struct {
	SessionData webauthn.SessionData `json:"sessionData"`
}

const TokenTypeResourceRegister = "resource_register"

type ResourceRegisterTokenManager struct {
	tokenManager managedTokenManager[ResourceRegisterContent]
}

func newRegisterTokenManager(services *Services) *ResourceRegisterTokenManager {
	cfg := tokenConfig(services)
	return &ResourceRegisterTokenManager{
		tokenManager: newManagedTokenManager[ResourceRegisterContent](services, TokenTypeResourceRegister, tokenDuration(cfg.ResourceRegister.Duration, defaultTokenConfig().ResourceRegister.Duration)),
	}
}

func (m *ResourceRegisterTokenManager) GetExpirationInSeconds() int {
	return int(m.tokenManager.expiresIn.Seconds())
}

func (m *ResourceRegisterTokenManager) New(data ResourceRegisterContent) (string, error) {
	return m.tokenManager.New(data)
}

func (m *ResourceRegisterTokenManager) Get(token string) (ResourceRegisterContent, error) {
	return m.tokenManager.Get(token)
}

func (m *ResourceRegisterTokenManager) Set(token string, data ResourceRegisterContent) error {
	return m.tokenManager.Set(token, data)
}

func (m *ResourceRegisterTokenManager) Revoke(token string) error {
	return m.tokenManager.Revoke(token)
}

func (m *ResourceRegisterTokenManager) IsRevoked(token string) bool {
	return m.tokenManager.IsRevoked(token)
}
