package tokens

import (
	"time"
)

type ChallengeContent struct {
	GlobalTokenPayload

	// IsWebAuthnFlow restricts the challenge to WebAuthn authenticators.
	IsWebAuthnFlow bool `json:"isWebAuthnFlow"`

	UserID           string   `json:"userId"`
	PassedChallenges []string `json:"passedChallenges"`

	// Challenge Info
	ChallengeIds       []string `json:"challengeIds"`
	ChallengeResponse  string   `json:"challengeResponse"`
	ChallengeExpiresAt int64    `json:"challengeExpiresAt"`
}

func (c *ChallengeContent) MarkAsPassed(challengeId string) {
	c.PassedChallenges = append(c.PassedChallenges, challengeId)
}

func (c *ChallengeContent) SetChallenge(challengeIds []string, challengeResponse string, expiresAt time.Time) {
	c.ChallengeIds = challengeIds
	c.ChallengeResponse = challengeResponse
	c.ChallengeExpiresAt = expiresAt.UnixMilli()
}

func (c *ChallengeContent) IsExpired() bool {
	return time.Now().UnixMilli() > c.ChallengeExpiresAt
}

func (c *ChallengeContent) ResetChallenge() {
	c.ChallengeIds = []string{}
	c.ChallengeResponse = ""
	c.ChallengeExpiresAt = 0
}

func (c *ChallengeContent) IsPassed(challengeId string) bool {
	for _, passedChallenge := range c.PassedChallenges {
		if passedChallenge == challengeId {
			return true
		}
	}

	return false
}

type ChallengeManager struct {
	tokenManager managedTokenManager[ChallengeContent]
}

const TokenTypeChallenge = "challenge"

func newChallengeManager(services *Services) *ChallengeManager {
	return &ChallengeManager{
		tokenManager: newManagedTokenManager[ChallengeContent](services, TokenTypeChallenge, 0),
	}
}

func (m *ChallengeManager) New(data ChallengeContent) (string, error) {
	return m.tokenManager.New(data)
}

func (m *ChallengeManager) Get(token string) (ChallengeContent, error) {
	return m.tokenManager.Get(token)
}

func (m *ChallengeManager) Set(token string, data ChallengeContent) error {
	return m.tokenManager.Set(token, data)
}

func (m *ChallengeManager) Revoke(token string) error {
	return m.tokenManager.Revoke(token)
}

func (m *ChallengeManager) IsRevoked(token string) bool {
	return m.tokenManager.IsRevoked(token)
}
