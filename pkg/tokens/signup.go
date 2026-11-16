package tokens

import (
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"time"
)

type OwnershipTokenContent struct {
	GlobalTokenPayload

	Email          string    `json:"email"`
	EmailChallenge string    `json:"emailChallenge"`
	EmailVerified  bool      `json:"emailVerified"`
	EmailExpiresAt time.Time `json:"emailExpiresAt"`

	Phone          string    `json:"phone"`
	PhoneChallenge string    `json:"phoneChallenge"`
	PhoneVerified  bool      `json:"phoneVerified"`
	PhoneExpiresAt time.Time `json:"phoneExpiresAt"`
}

func (c *OwnershipTokenContent) IsEmailVerified(email string) bool {
	return c.IsAnyOfEmailVerified(email)
}

func (c *OwnershipTokenContent) IsAnyOfEmailVerified(emails ...string) bool {
	return utils.Contains(emails, c.Email) && c.EmailVerified
}

func (c *OwnershipTokenContent) IsPhoneVerified(phone string) bool {
	return c.IsAnyOfPhoneVerified(phone)
}

func (c *OwnershipTokenContent) IsAnyOfPhoneVerified(phones ...string) bool {
	return utils.Contains(phones, c.Phone) && c.PhoneVerified
}

func (c *OwnershipTokenContent) VerifyEmailChallenge(email string, challenge string) bool {
	return c.Email != "" && c.Email == email && c.EmailChallenge == challenge && !c.IsEmailExpired()
}

func (c *OwnershipTokenContent) VerifyPhoneChallenge(phone string, challenge string) bool {
	return c.Phone != "" && c.Phone == phone && c.PhoneChallenge == challenge && !c.IsPhoneExpired()
}

func (c *OwnershipTokenContent) IsExpired() bool {
	return c.ExpiresAt.Before(time.Now())
}

func (c *OwnershipTokenContent) IsEmailExpired() bool {
	return c.EmailExpiresAt.Before(time.Now())
}

func (c *OwnershipTokenContent) IsPhoneExpired() bool {
	return c.PhoneExpiresAt.Before(time.Now())
}

func (c *OwnershipTokenContent) SetEmailChallenge(email string, challenge string) {
	c.SetEmailChallengeWithDuration(email, challenge, defaultTokenConfig().OwnershipChallenge.Duration)
}

func (c *OwnershipTokenContent) SetEmailChallengeWithDuration(email string, challenge string, duration time.Duration) {
	c.Email = email
	c.EmailChallenge = challenge
	c.EmailVerified = false
	c.EmailExpiresAt = time.Now().Add(duration)
}

func (c *OwnershipTokenContent) SetPhoneChallenge(phone string, challenge string) {
	c.SetPhoneChallengeWithDuration(phone, challenge, defaultTokenConfig().OwnershipChallenge.Duration)
}

func (c *OwnershipTokenContent) SetPhoneChallengeWithDuration(phone string, challenge string, duration time.Duration) {
	c.Phone = phone
	c.PhoneChallenge = challenge
	c.PhoneVerified = false
	c.PhoneExpiresAt = time.Now().Add(duration)
}

const TokenTypeSignUp = "sign_up"

type OwnershipTokenManager struct {
	tokenManager managedTokenManager[OwnershipTokenContent]
}

func newOwnershipTokenManager(services *Services) *OwnershipTokenManager {
	cfg := tokenConfig(services)
	return &OwnershipTokenManager{
		tokenManager: newManagedTokenManager[OwnershipTokenContent](services, TokenTypeSignUp, tokenDuration(cfg.OwnershipToken.Duration, defaultTokenConfig().OwnershipToken.Duration)),
	}
}

func (m *OwnershipTokenManager) GetExpirationInSeconds() int {
	return int(m.tokenManager.expiresIn.Seconds())
}

func (m *OwnershipTokenManager) ChallengeDuration() time.Duration {
	cfg := tokenConfig(m.tokenManager.tokenManager.services)
	return tokenDuration(cfg.OwnershipChallenge.Duration, defaultTokenConfig().OwnershipChallenge.Duration)
}

func (m *OwnershipTokenManager) New(data OwnershipTokenContent) (string, error) {
	return m.tokenManager.New(data)
}

func (m *OwnershipTokenManager) Get(token string) (OwnershipTokenContent, error) {
	return m.tokenManager.Get(token)
}

func (m *OwnershipTokenManager) Set(token string, data OwnershipTokenContent) error {
	return m.tokenManager.Set(token, data)
}

func (m *OwnershipTokenManager) Revoke(token string) error {
	return m.tokenManager.Revoke(token)
}

func (m *OwnershipTokenManager) IsRevoked(token string) bool {
	return m.tokenManager.IsRevoked(token)
}
