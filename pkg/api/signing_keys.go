package api

import (
	"maps"

	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

func signingKeyResponse(authenticator database.UserAuthenticator) types.SigningKeyResponse {
	fingerprint, _ := authenticator.Data["fingerprint"].(string)
	public, _ := authenticator.Data["public"].(bool)
	return types.SigningKeyResponse{ID: authenticator.ID.String(), Note: authenticator.Note, Fingerprint: fingerprint, Public: public}
}

// GetUserSigningKeys lists the user's signing keys of kind (database.PGPKeyType
// or database.SSHKeyType).
func GetUserSigningKeys(caller *tokens.Principal, userID, kind string) ([]types.SigningKeyResponse, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return nil, err
	}
	return utils.Map(user.GetAuthenticators(kind), signingKeyResponse), nil
}

// AddUserSigningKey registers a signing key of kind for the user.
func AddUserSigningKey(caller *tokens.Principal, userID, kind string, body types.AddSigningKeyRequest) (types.SigningKeyResponse, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return types.SigningKeyResponse{}, err
	}

	authenticator, err := user.AddSigningKey(kind, body.Key, body.Note, body.Public)
	if err != nil {
		return types.SigningKeyResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
	}

	db, err := getDB()
	if err != nil {
		return types.SigningKeyResponse{}, err
	}
	if err := db.Create(authenticator).Error; err != nil {
		return types.SigningKeyResponse{}, meilingErrors.NewInternalServerError("failed to add signing key", err)
	}
	return signingKeyResponse(*authenticator), nil
}

// RemoveUserSigningKey deletes the user's signing key of kind with keyID.
func RemoveUserSigningKey(caller *tokens.Principal, userID, kind, keyID string) error {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return err
	}

	authenticator, found := utils.Find(user.Authenticators, func(item database.UserAuthenticator) bool {
		return item.ID.String() == keyID && item.Type == kind
	})
	if !found {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "key_id is not found")
	}

	db, err := getDB()
	if err != nil {
		return err
	}
	if err := db.Delete(&authenticator).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to delete signing key", err)
	}

	user.Authenticators = utils.Filter(user.Authenticators, func(item database.UserAuthenticator) bool {
		return item.ID != authenticator.ID
	})
	if !user.HasTwoFactorAuthn() {
		if err := user.DisableTwoFactor(); err != nil {
			return meilingErrors.NewInternalServerError("failed to disable two factor", err)
		}
	}
	return nil
}

// UpdateUserSigningKey changes the note of the user's signing key of kind, or
// whether it is public.
func UpdateUserSigningKey(caller *tokens.Principal, userID, kind, keyID string, body types.UpdateSigningKeyRequest) (types.SigningKeyResponse, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return types.SigningKeyResponse{}, err
	}

	authenticator, found := utils.Find(user.Authenticators, func(item database.UserAuthenticator) bool {
		return item.ID.String() == keyID && item.Type == kind
	})
	if !found {
		return types.SigningKeyResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "key_id is not found")
	}

	if body.Note != nil {
		authenticator.Note = *body.Note
	}
	if body.Public != nil {
		data := maps.Clone(authenticator.Data)
		data["public"] = *body.Public
		authenticator.Data = data
	}
	db, err := getDB()
	if err != nil {
		return types.SigningKeyResponse{}, err
	}
	if err := db.Model(&authenticator).Select("note", "data").Updates(&authenticator).Error; err != nil {
		return types.SigningKeyResponse{}, meilingErrors.NewInternalServerError("failed to update signing key", err)
	}
	return signingKeyResponse(authenticator), nil
}
