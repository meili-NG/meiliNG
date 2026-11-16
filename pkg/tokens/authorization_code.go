package tokens

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// ===== CODE CHALLENGE =====

type CodeChallengeMethod string

const SHA256CodeChallenge CodeChallengeMethod = "S256"
const PlainCodeChallenge CodeChallengeMethod = "plain"

func NewCodeChallengeMethod(s string) (CodeChallengeMethod, error) {
	switch s {
	case "S256":
		return SHA256CodeChallenge, nil
	case "plain":
		return PlainCodeChallenge, nil
	default:
		return "", errors.New("invalid code challenge method")
	}
}

type CodeChallengeState struct {
	Challenge string              `json:"challenge"`
	Method    CodeChallengeMethod `json:"method"`
}

// ===== AUTHORIZATION =====

type AuthorizationCodeContent struct {
	GlobalTokenPayload

	UserID             string              `json:"userId"`
	ClientID           string              `json:"clientId"`
	Permissions        []string            `json:"permissions"`
	State              string              `json:"state"`
	CodeChallengeState *CodeChallengeState `json:"codeChallenge"`
	AccessType         string              `json:"accessType"`

	Nonce string `json:"nonce"`
	// Auth is how the user signed in, for the ID token; nil when unknown.
	Auth *AuthContext `json:"auth,omitempty"`
}

func (c *AuthorizationCodeContent) VerifyCodeVerifier(codeVerifier string) bool {
	if c.CodeChallengeState == nil {
		return codeVerifier == ""
	}

	if c.CodeChallengeState.Method == SHA256CodeChallenge {
		hasher := sha256.New()
		hasher.Write([]byte(codeVerifier))
		hashed := hasher.Sum([]byte{})

		base64Decoded, err := base64.RawURLEncoding.DecodeString(c.CodeChallengeState.Challenge)
		if err != nil {
			// try decoding with url encoding with padding
			base64Decoded, err = base64.URLEncoding.DecodeString(c.CodeChallengeState.Challenge)
			if err != nil {
				// try fallback with standard encoding
				base64Decoded, err = base64.StdEncoding.DecodeString(c.CodeChallengeState.Challenge)
				if err != nil {
					return false
				}
			}
		}

		// check base64Decoded and hashed is the same
		if len(base64Decoded) != len(hashed) {
			return false
		}

		for i := range base64Decoded {
			if base64Decoded[i] != hashed[i] {
				return false
			}
		}

		return true
	} else if c.CodeChallengeState.Method == PlainCodeChallenge {
		return c.CodeChallengeState.Challenge == codeVerifier
	} else {
		return false
	}
}

type AuthorizationCodeManager struct {
	tokenManager managedTokenManager[AuthorizationCodeContent]
}

const TokenTypeAuthorizationCode = "oauth2_authorization_code"

func newAuthorizationCodeManager(services *Services) *AuthorizationCodeManager {
	cfg := tokenConfig(services)
	return &AuthorizationCodeManager{
		tokenManager: newManagedTokenManager[AuthorizationCodeContent](services, TokenTypeAuthorizationCode, tokenDuration(cfg.AuthorizationCode.Duration, defaultTokenConfig().AuthorizationCode.Duration)),
	}
}

func (c *AuthorizationCodeContent) IsClient(clientID string) bool {
	return c.ClientID == clientID
}

func (c *AuthorizationCodeContent) HasCodeChallenge() bool {
	return c.CodeChallengeState != nil
}

func (m *AuthorizationCodeManager) New(data AuthorizationCodeContent) (string, error) {
	return m.tokenManager.New(data)
}

func (m *AuthorizationCodeManager) Get(token string) (AuthorizationCodeContent, error) {
	return m.tokenManager.Get(token)
}

func (m *AuthorizationCodeManager) Set(token string, data AuthorizationCodeContent) error {
	return m.tokenManager.Set(token, data)
}

func (m *AuthorizationCodeManager) Revoke(token string) error {
	return m.tokenManager.Revoke(token)
}

func (m *AuthorizationCodeManager) IsRevoked(token string) bool {
	return m.tokenManager.IsRevoked(token)
}

// ClaimOnce reports whether this call is the first to redeem token.
func (m *AuthorizationCodeManager) ClaimOnce(token string) (bool, error) {
	return m.tokenManager.tokenManager.ClaimOnce(token)
}
