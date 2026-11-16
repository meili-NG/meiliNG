package database

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/pkg/auth/signature"
)

// Authenticator types of signing keys.
const (
	PGPKeyType = "pgp"
	SSHKeyType = "ssh"
)

// SigningKeyValidator proves possession of an OpenPGP or SSH private key: the
// user signs a nonce the server issues with the key they registered.
type SigningKeyValidator struct {
	UserAuthValidator
	id   uuid.UUID
	kind string
	// PublicKey is an armored OpenPGP key, or an SSH key in authorized_keys form.
	PublicKey   string
	Fingerprint string
	// Public publishes the key at /{username}.keys or .gpg and on /pks/lookup.
	Public bool
}

// NewSigningKeyValidator checks publicKey for kind and returns its validator.
func NewSigningKeyValidator(kind, publicKey string) (*SigningKeyValidator, error) {
	var key, fingerprint string
	var err error
	switch kind {
	case PGPKeyType:
		key = strings.TrimSpace(publicKey)
		fingerprint, err = signature.ParsePGPKey(key)
	case SSHKeyType:
		key, fingerprint, err = signature.ParseSSHKey(publicKey)
	default:
		return nil, errors.New("unknown signing key type")
	}
	if err != nil {
		return nil, err
	}
	return &SigningKeyValidator{kind: kind, PublicKey: key, Fingerprint: fingerprint}, nil
}

func (validator *SigningKeyValidator) Type() string {
	return validator.kind
}

func (validator *SigningKeyValidator) RequireChallenge() bool {
	return true
}

// IssueChallenge returns the nonce to sign, which is also what is expected
// back inside the signature.
func (validator *SigningKeyValidator) IssueChallenge() (string, string, error) {
	nonce := utils.RandomString(32)
	return nonce, nonce, nil
}

func (validator *SigningKeyValidator) ValidateChallenge(response string, expected string) (bool, error) {
	if expected == "" {
		return false, nil
	}
	if validator.kind == PGPKeyType {
		return signature.VerifyPGP(validator.PublicKey, response, expected)
	}
	return signature.VerifySSH(validator.PublicKey, response, expected)
}

func (validator *SigningKeyValidator) SerializeAuthenticator() (*UserAuthenticator, error) {
	return &UserAuthenticator{
		UserAuthenticatorFields: models.UserAuthenticatorFields{
			ID:   validator.GetID(),
			Type: validator.Type(),
			Data: map[string]any{
				"key":         validator.PublicKey,
				"fingerprint": validator.Fingerprint,
				"public":      validator.Public,
			},
			Identifier: &validator.Fingerprint,
			// Like a passkey: proving possession of the key is enough.
			AllowSignIn:       false,
			Allow2FA:          true,
			AllowPasswordless: true,
		},
	}, nil
}

func (validator *SigningKeyValidator) GetExpiresAt() time.Time {
	return time.Now().Add(10 * time.Minute)
}

func (validator *SigningKeyValidator) GetID() uuid.UUID {
	if validator.id == uuid.Nil {
		validator.id = uuid.New()
	}
	return validator.id
}

func (validator *SigningKeyValidator) Update() error {
	return nil
}

func (auth *UserAuthenticator) GetSigningKeyValidator() (*SigningKeyValidator, error) {
	key, _ := auth.Data["key"].(string)
	fingerprint, _ := auth.Data["fingerprint"].(string)
	public, _ := auth.Data["public"].(bool)
	if key == "" {
		return nil, errors.New("invalid signing key")
	}
	return &SigningKeyValidator{id: auth.ID, kind: auth.Type, PublicKey: key, Fingerprint: fingerprint, Public: public}, nil
}

// AddSigningKey registers publicKey of kind, refusing one already registered.
func (u *User) AddSigningKey(kind, publicKey, note string, public bool) (*UserAuthenticator, error) {
	validator, err := NewSigningKeyValidator(kind, publicKey)
	if err != nil {
		return nil, err
	}
	validator.Public = public
	for _, existing := range u.GetAuthenticators(kind) {
		if existing.Identifier != nil && *existing.Identifier == validator.Fingerprint {
			return nil, errors.New("this key is already registered")
		}
	}

	authn, err := validator.SerializeAuthenticator()
	if err != nil {
		return nil, err
	}
	authn.UserID = u.ID
	authn.Note = note
	u.AddAuthenticator(authn)
	return authn, nil
}
