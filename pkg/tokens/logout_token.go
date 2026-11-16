package tokens

import (
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// TokenTypeLogoutToken is the token_type private claim of logout tokens.
const TokenTypeLogoutToken = "logout_token"

// BackchannelLogoutEvent is the event a logout token carries (OpenID Connect
// Back-Channel Logout 1.0).
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutTokenClaims is the payload of a logout token.
type LogoutTokenClaims struct {
	jwt.Claims
	SID    string                    `json:"sid,omitempty"`
	Events map[string]map[string]any `json:"events"`
}

// GenerateLogoutToken signs a logout token telling clientID that userID
// signed out of the session sid.
func GenerateLogoutToken(services *Services, clientID, userID, sid string) (string, error) {
	manager := services.JWT()
	now := time.Now()
	claims := LogoutTokenClaims{
		Claims: jwt.Claims{
			ID:       uuid.New().String(),
			Issuer:   manager.Issuer(),
			Subject:  userID,
			Audience: jwt.Audience{clientID},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(2 * time.Minute)),
		},
		SID:    sid,
		Events: map[string]map[string]any{BackchannelLogoutEvent: {}},
	}
	return manager.GenerateTokenFromCustomClaims(claims, TokenTypeLogoutToken)
}
