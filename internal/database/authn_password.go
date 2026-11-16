package database

import (
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	authpassword "github.com/meili-NG/meiliNG/v2/pkg/auth/password"
)

type PasswordValidator struct {
	UserAuthValidator
	id           uuid.UUID
	PasswordType string
	Data         string
}

func (validator *PasswordValidator) Type() string {
	return "password"
}

func (validator *PasswordValidator) RequireChallenge() bool {
	return false
}

func (validator *PasswordValidator) IssueChallenge() (string, string, error) {
	return "", "", nil
}

func (validator *PasswordValidator) ValidateChallenge(response string, expected string) (bool, error) {
	return validator.ValidatePassword(response)
}

func (validator *PasswordValidator) ValidatePassword(data any) (bool, error) {
	password, ok := data.(string)
	if !ok {
		return false, nil
	}
	return authpassword.Verify(validator.PasswordType, validator.Data, password)
}

func (validator *PasswordValidator) SerializeData() map[string]any {
	return map[string]any{
		"type": validator.PasswordType,
		"data": validator.Data,
	}
}

func (validator *PasswordValidator) SerializeAuthenticator() (*UserAuthenticator, error) {
	return &UserAuthenticator{
		UserAuthenticatorFields: models.UserAuthenticatorFields{
			ID:                validator.GetID(),
			Type:              validator.Type(),
			Data:              validator.SerializeData(),
			Identifier:        validator.GetIdentifier(),
			AllowSignIn:       true,
			AllowPasswordless: false,
			Allow2FA:          false,
		},
	}, nil
}

func (validator *PasswordValidator) GetExpiresAt() time.Time {
	return time.Now().Add(time.Hour * 24)
}

func (validator *PasswordValidator) GetIdentifier() *string {
	return nil
}

func (validator *PasswordValidator) GetID() uuid.UUID {
	if validator.id == uuid.Nil {
		validator.id = uuid.New()
	}

	return validator.id
}

func (validator *PasswordValidator) Update() error {
	return nil
}
