package api

import (
	"encoding/hex"
	"strings"

	"github.com/meili-NG/meiliNG/v2/internal/database"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
)

// PublicSigningKeys returns the signing keys of kind the user with username
// marked public. A user that does not exist has none, so the answer does not
// reveal which usernames exist.
func PublicSigningKeys(username, kind string) ([]string, error) {
	user, err := (&database.UserFinder{}).FindByUserName(username)
	if err != nil || user == nil {
		return nil, err
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}
	var authenticators []database.UserAuthenticator
	if err := db.Where("user_id = ? AND type = ?", user.ID, kind).Order("id").Find(&authenticators).Error; err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to load keys", err)
	}
	return publicKeys(authenticators), nil
}

// PublicPGPKey returns the public OpenPGP key whose fingerprint is search, or
// ends with it as a 16-digit key ID. An optional 0x prefix is accepted.
func PublicPGPKey(search string) (string, error) {
	id := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(search, "0x"), "0X"))
	if _, err := hex.DecodeString(id); err != nil || (len(id) != 16 && len(id) != 40) {
		return "", nil
	}

	db, err := getDB()
	if err != nil {
		return "", err
	}
	var authenticators []database.UserAuthenticator
	if err := db.Where("type = ? AND identifier LIKE ?", database.PGPKeyType, "%"+id).Find(&authenticators).Error; err != nil {
		return "", meilingErrors.NewInternalServerError("failed to load keys", err)
	}
	if keys := publicKeys(authenticators); len(keys) > 0 {
		return keys[0], nil
	}
	return "", nil
}

func publicKeys(authenticators []database.UserAuthenticator) []string {
	keys := []string{}
	for _, authenticator := range authenticators {
		if validator, err := authenticator.GetSigningKeyValidator(); err == nil && validator.Public {
			keys = append(keys, validator.PublicKey)
		}
	}
	return keys
}

// KeyOwner is the owner of a public signing key.
type KeyOwner struct {
	Type        string
	Fingerprint string
	Username    string
}

// PublicKeyOwner finds who owns the public signing key with fingerprint: an
// SSH SHA256 fingerprint, or a 40-digit OpenPGP fingerprint. It returns nil
// when no public key matches or its owner has no username, so private keys
// and email addresses are never revealed.
func PublicKeyOwner(fingerprint string) (*KeyOwner, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return nil, nil
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}
	var authenticators []database.UserAuthenticator
	if err := db.Where("type IN ? AND identifier IN ?",
		[]string{database.PGPKeyType, database.SSHKeyType},
		[]string{fingerprint, strings.ToLower(fingerprint)},
	).Find(&authenticators).Error; err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to load keys", err)
	}

	for _, authenticator := range authenticators {
		validator, err := authenticator.GetSigningKeyValidator()
		if err != nil || !validator.Public {
			continue
		}
		user, err := findUserByID(authenticator.UserID.String())
		if err != nil {
			continue
		}
		for _, name := range user.UserNames {
			if name.Username != "" {
				return &KeyOwner{Type: authenticator.Type, Fingerprint: validator.Fingerprint, Username: name.Username}, nil
			}
		}
	}
	return nil, nil
}
