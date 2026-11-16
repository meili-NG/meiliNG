package tokens

import "github.com/meili-NG/meiliNG/v2/pkg/ext"

// ===== AUTHORIZATION =====

type AccessTokenContent struct {
	GlobalTokenPayload

	UserID       string   `json:"userId"`
	ClientID     string   `json:"clientId"`
	Permissions  []string `json:"permissions,omitempty"`
	ConsentLogID string   `json:"consentLogId"`

	// JWT claim metadata
	GrantType string `json:"grantType"`
	// Claims are private claims AccessTokenClaims added at issuance.
	Claims   map[string]any `json:"claims,omitempty"`
	Audience []string       `json:"audience,omitempty"`
	Scope    string         `json:"scope,omitempty"`
}

const TokenTypeAccessToken = "oauth2_access_token"

// AccessTokenClaimsFunc returns private claims to add to an access token
// issued to clientID, for userID or, from client_credentials, for no user.
type AccessTokenClaimsFunc func(clientID, userID string) map[string]any

// AccessTokenClaims lets a distribution add private claims to every access
// token, under the claims namespace, e.g. from the application's metadata. It
// cannot replace a claim core sets. Unset adds none.
var AccessTokenClaims = ext.NewSlot[AccessTokenClaimsFunc](nil)

type AccessTokenManager struct {
	tokenManager managedTokenManager[AccessTokenContent]
}

func newAccessTokenManager(services *Services) *AccessTokenManager {
	cfg := tokenConfig(services)
	return &AccessTokenManager{
		tokenManager: newManagedTokenManager[AccessTokenContent](services, TokenTypeAccessToken, tokenDuration(cfg.AccessToken.Duration, defaultTokenConfig().AccessToken.Duration)),
	}
}

func (m *AccessTokenManager) GetExpirationInSeconds() int {
	return int(m.tokenManager.expiresIn.Seconds())
}

func (m *AccessTokenManager) New(data AccessTokenContent) (string, error) {
	if add := AccessTokenClaims.Get(); add != nil && data.Claims == nil {
		data.Claims = add(data.ClientID, data.UserID)
	}
	return m.tokenManager.New(data)
}

func (m *AccessTokenManager) Get(token string) (AccessTokenContent, error) {
	return m.tokenManager.Get(token)
}

func (m *AccessTokenManager) Set(token string, data AccessTokenContent) error {
	return m.tokenManager.Set(token, data)
}

func (m *AccessTokenManager) Revoke(token string) error {
	return m.tokenManager.Revoke(token)
}

func (m *AccessTokenManager) IsRevoked(token string) bool {
	return m.tokenManager.IsRevoked(token)
}
