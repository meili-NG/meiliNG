package database

import (
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/pquerna/otp/totp"
)

type TOTPValidator struct {
	UserAuthValidator
	id     uuid.UUID
	Secret string
}

func (validator *TOTPValidator) Type() string {
	return "totp"
}

func (validator *TOTPValidator) Validate(data any) (bool, error) {
	code, ok := data.(string)
	if !ok {
		return false, nil
	}

	return validator.CheckTOTP(code)
}

func (validator *TOTPValidator) RequireChallenge() bool {
	return false
}

func (validator *TOTPValidator) IssueChallenge() (string, string, error) {
	return "", "", nil
}

func (validator *TOTPValidator) ValidateChallenge(response string, expected string) (bool, error) {
	return validator.Validate(response)
}

func (validator *TOTPValidator) CheckTOTP(code string) (bool, error) {
	// validator.Secret == TOTP secret, code == TOTP code
	return totp.Validate(code, validator.Secret), nil
}

func (validator *TOTPValidator) SerializeData() map[string]any {
	return map[string]any{
		"secret": validator.Secret,
	}
}

func (validator *TOTPValidator) SerializeAuthenticator() (*UserAuthenticator, error) {
	return &UserAuthenticator{
		UserAuthenticatorFields: models.UserAuthenticatorFields{
			ID:                validator.GetID(),
			Type:              validator.Type(),
			Data:              validator.SerializeData(),
			AllowSignIn:       false,
			Allow2FA:          true,
			AllowPasswordless: false,
		},
	}, nil
}

func (validator *TOTPValidator) GetExpiresAt() time.Time {
	return time.Now().Add(time.Minute * 10)
}
func (validator *TOTPValidator) GetID() uuid.UUID {
	if validator.id == uuid.Nil {
		validator.id = uuid.New()
	}

	return validator.id
}

func (validator *TOTPValidator) Update() error {
	return nil
}
