package database

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"golang.org/x/crypto/bcrypt"
)

const BackupCodeType = "backup_code"

type BackupCodeValidator struct {
	UserAuthValidator
	id        uuid.UUID
	Hash      string
	CreatedAt time.Time
	UsedAt    *time.Time
}

func (validator *BackupCodeValidator) Type() string {
	return BackupCodeType
}

func (validator *BackupCodeValidator) RequireChallenge() bool {
	return false
}

func (validator *BackupCodeValidator) IssueChallenge() (string, string, error) {
	return "", "", nil
}

func (validator *BackupCodeValidator) ValidateChallenge(response string, expected string) (bool, error) {
	return validator.ValidateBackupCode(response)
}

func (validator *BackupCodeValidator) ValidateBackupCode(code string) (bool, error) {
	if validator.IsUsed() {
		return false, nil
	}

	normalized := NormalizeBackupCode(code)
	if normalized == "" || validator.Hash == "" {
		return false, nil
	}

	err := bcrypt.CompareHashAndPassword([]byte(validator.Hash), []byte(normalized))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (validator *BackupCodeValidator) IsUsed() bool {
	return validator.UsedAt != nil && !validator.UsedAt.IsZero()
}

func (validator *BackupCodeValidator) SerializeData() map[string]any {
	createdAt := validator.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		validator.CreatedAt = createdAt
	}

	data := map[string]any{
		"hash":      validator.Hash,
		"createdAt": createdAt.UTC().Format(time.RFC3339Nano),
	}
	if validator.IsUsed() {
		data["usedAt"] = validator.UsedAt.UTC().Format(time.RFC3339Nano)
	}
	return data
}

func (validator *BackupCodeValidator) SerializeAuthenticator() (*UserAuthenticator, error) {
	return &UserAuthenticator{
		UserAuthenticatorFields: models.UserAuthenticatorFields{
			ID:                validator.GetID(),
			Type:              validator.Type(),
			Data:              validator.SerializeData(),
			AllowSignIn:       false,
			Allow2FA:          true,
			AllowPasswordless: false,
			Note:              "backup-code",
		},
	}, nil
}

func (validator *BackupCodeValidator) GetExpiresAt() time.Time {
	return time.Now().Add(time.Minute * 10)
}

func (validator *BackupCodeValidator) GetID() uuid.UUID {
	if validator.id == uuid.Nil {
		validator.id = uuid.New()
	}

	return validator.id
}

func (validator *BackupCodeValidator) Update() error {
	if validator.IsUsed() {
		return nil
	}

	usedAt := time.Now().UTC()
	validator.UsedAt = &usedAt

	db, err := GetDatabase()
	if err != nil {
		return err
	}

	authenticator, err := validator.SerializeAuthenticator()
	if err != nil {
		return err
	}

	return db.Updates(authenticator).Error
}

func NewBackupCodeValidator(code string) (*BackupCodeValidator, error) {
	normalized := NormalizeBackupCode(code)
	hash, err := bcrypt.GenerateFromPassword([]byte(normalized), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return &BackupCodeValidator{
		Hash:      string(hash),
		CreatedAt: time.Now().UTC(),
	}, nil
}

func GenerateBackupCodes(count int, codeBytes int) ([]string, error) {
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		code, err := GenerateBackupCode(codeBytes)
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

func GenerateBackupCode(codeBytes int) (string, error) {
	raw := make([]byte, codeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return FormatBackupCode(encoded), nil
}

func FormatBackupCode(code string) string {
	normalized := NormalizeBackupCode(code)
	if len(normalized) <= 4 {
		return normalized
	}

	parts := make([]string, 0, (len(normalized)+3)/4)
	for len(normalized) > 4 {
		parts = append(parts, normalized[:4])
		normalized = normalized[4:]
	}
	if normalized != "" {
		parts = append(parts, normalized)
	}
	return strings.Join(parts, "-")
}

func NormalizeBackupCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToUpper(r)
	}, code)
}
