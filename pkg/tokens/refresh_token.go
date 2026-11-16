package tokens

// ===== AUTHORIZATION =====

type RefreshTokenContent struct {
	GlobalTokenPayload

	UserID       string   `json:"userId"`
	ClientID     string   `json:"clientId"`
	Permissions  []string `json:"permissions,omitempty"`
	ConsentLogID string   `json:"consentLogId"`
}

const TokenTypeRefreshToken = "oauth2_refresh_token"

type RefreshTokenManager struct {
	tokenManager managedTokenManager[RefreshTokenContent]
}

func newRefreshTokenManager(services *Services) *RefreshTokenManager {
	cfg := tokenConfig(services)
	return &RefreshTokenManager{
		tokenManager: newManagedTokenManager[RefreshTokenContent](services, TokenTypeRefreshToken, tokenDuration(cfg.RefreshToken.Duration, defaultTokenConfig().RefreshToken.Duration)),
	}
}

func (m *RefreshTokenManager) New(data RefreshTokenContent) (string, error) {
	return m.tokenManager.New(data)
}

func (m *RefreshTokenManager) GetExpirationInSeconds() int {
	return int(m.tokenManager.expiresIn.Seconds())
}

func (m *RefreshTokenManager) Get(token string) (RefreshTokenContent, error) {
	return m.tokenManager.Get(token)
}

func (m *RefreshTokenManager) Set(token string, data RefreshTokenContent) error {
	return m.tokenManager.Set(token, data)
}

func (m *RefreshTokenManager) Revoke(token string) error {
	return m.tokenManager.Revoke(token)
}

func (m *RefreshTokenManager) IsRevoked(token string) bool {
	return m.tokenManager.IsRevoked(token)
}

// ConsentLogIDIncludingRevoked reads the consentLogId stored for a refresh
// token even if that token has already been revoked (e.g. rotated). This is
// used for refresh-token reuse detection: when a rotated (revoked) refresh
// token is replayed, the caller can look up the owning consent log and revoke
// the whole token lineage. It only extracts the consentLogId string, so it is
// unaffected by the revokedAt storage-shape differences between the Valkey and
// in-memory fallback stores.
func (m *RefreshTokenManager) ConsentLogIDIncludingRevoked(token string) (string, error) {
	return m.tokenManager.consentLogIDIncludingRevoked(token)
}
