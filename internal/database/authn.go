package database

import (
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type UserAuthValidator interface {
	GetID() uuid.UUID

	Type() string
	SerializeAuthenticator() (*UserAuthenticator, error)

	RequireChallenge() bool
	IssueChallenge() (challenge string, response string, err error)
	ValidateChallenge(response string, expected string) (bool, error)

	GetExpiresAt() time.Time
	Update() error
}

type UserAuthenticator struct {
	models.UserAuthenticatorFields `gorm:"embedded"`
}

func (auth *UserAuthenticator) BeforeCreate(tx *gorm.DB) error {
	if auth.ID == uuid.Nil {
		auth.ID = uuid.New()
	}

	if auth.Data == nil {
		auth.Data = map[string]any{}
	}

	return nil
}

func (auth *UserAuthenticator) CanBeUsedFor(challengeType string) bool {
	switch challengeType {
	case "passwordless":
		return auth.AllowPasswordless
	case "2fa":
		return auth.Allow2FA
	case "signin":
		return auth.AllowSignIn
	}
	return false
}

func (auth *UserAuthenticator) GetValidator() (UserAuthValidator, error) {
	switch auth.Type {
	case (&PasswordValidator{}).Type():
		return auth.GetPasswordValidator()
	case (&TOTPValidator{}).Type():
		return auth.GetTOTPValidator()
	case (&WebAuthnValidator{}).Type():
		return auth.GetWebAuthnValidator()
	case (&BackupCodeValidator{}).Type():
		return auth.GetBackupCodeValidator()
	case PGPKeyType, SSHKeyType:
		return auth.GetSigningKeyValidator()
	}
	return nil, errors.New("unknown authenticator type")
}

func (auth *UserAuthenticator) GetPasswordValidator() (*PasswordValidator, error) {
	data := auth.Data

	// validate data and check type
	if v, ok := data["type"].(string); !ok || v == "" {
		return nil, errors.New("invalid password type")
	} else if v, ok := data["data"].(string); !ok || v == "" {
		return nil, errors.New("invalid password data (hash)")
	}

	return &PasswordValidator{
		id:           auth.ID,
		PasswordType: data["type"].(string),
		Data:         data["data"].(string),
	}, nil
}

func (auth *UserAuthenticator) GetTOTPValidator() (*TOTPValidator, error) {
	data := auth.Data

	// validate data and check type
	if v, ok := data["secret"].(string); !ok || v == "" {
		return nil, errors.New("invalid totp secret")
	}

	return &TOTPValidator{
		id:     auth.ID,
		Secret: data["secret"].(string),
	}, nil
}

func (auth *UserAuthenticator) GetBackupCodeValidator() (*BackupCodeValidator, error) {
	data := auth.Data

	hash, ok := data["hash"].(string)
	if !ok || hash == "" {
		return nil, errors.New("invalid backup code hash")
	}

	createdAt := time.Time{}
	if value, ok := data["createdAt"].(string); ok && value != "" {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return nil, errors.New("invalid backup code createdAt")
		}
		createdAt = parsed
	}

	var usedAt *time.Time
	if value, ok := data["usedAt"].(string); ok && value != "" {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return nil, errors.New("invalid backup code usedAt")
		}
		usedAt = &parsed
	}

	return &BackupCodeValidator{
		id:        auth.ID,
		Hash:      hash,
		CreatedAt: createdAt,
		UsedAt:    usedAt,
	}, nil
}

func (auth *UserAuthenticator) GetWebAuthnValidator() (*WebAuthnValidator, error) {
	data := auth.Data

	var target WebAuthnValidator
	err := target.DeserializeData(data)
	if err != nil {
		return nil, err
	}

	target.user, err = auth.GetUser()
	if err != nil {
		return nil, err
	}

	target.id = auth.ID

	return &target, nil
}

func (auth *UserAuthenticator) GetUser() (*User, error) {
	db, err := GetUserDB()
	if err != nil {
		return nil, err
	}

	var user User
	err = db.First(&user, "id = ?", auth.UserID).Error
	if err != nil {
		return nil, err
	}

	return &user, nil
}
