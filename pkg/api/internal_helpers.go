package api

import (
	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"gorm.io/gorm"
)

func getDB() (*gorm.DB, error) {
	db, err := database.GetDatabase()
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to get database", err)
	}
	return db, nil
}

func getUserDB() (*gorm.DB, error) {
	db, err := database.GetUserDB()
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to get database", err)
	}
	return db, nil
}

func getApplicationDB() (*gorm.DB, error) {
	db, err := database.GetApplicationDB()
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to get database", err)
	}
	return db, nil
}

func getOAuth2DB() (*gorm.DB, error) {
	db, err := database.GetOAuth2DB()
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to get database", err)
	}
	return db, nil
}

func getConsentLogDB() (*gorm.DB, error) {
	db, err := database.GetConsentLogDB()
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to get database", err)
	}
	return db, nil
}

func getConsentLogIDTokenDB() (*gorm.DB, error) {
	db, err := database.GetUserIDTokenFromConsentLogDB()
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to get database", err)
	}
	return db, nil
}

func findUserByID(userID string) (*database.User, error) {
	if userID == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user_id is required")
	}

	db, err := getUserDB()
	if err != nil {
		return nil, err
	}

	var user database.User
	if err := db.First(&user, "id = ?", userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound || user.ID == uuid.Nil {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "user not found")
		}
		return nil, meilingErrors.NewInternalServerError("failed to find user", err)
	}

	return &user, nil
}

func findApplicationByID(applicationID string) (*database.Application, error) {
	if applicationID == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "app_id is required")
	}

	db, err := getApplicationDB()
	if err != nil {
		return nil, err
	}

	var application database.Application
	if err := db.First(&application, "id = ?", applicationID).Error; err != nil {
		if err == gorm.ErrRecordNotFound || application.ID == uuid.Nil {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "application not found")
		}
		return nil, meilingErrors.NewInternalServerError("failed to find application", err)
	}

	return &application, nil
}

// findOAuth2ClientByID loads the OAuth2 client of the application whose ID is
// clientID, together with that application.
func findOAuth2ClientByID(clientID string) (*database.OauthClient, error) {
	if clientID == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "client_id is required")
	}

	db, err := getOAuth2DB()
	if err != nil {
		return nil, err
	}

	var client database.OauthClient
	if err := db.First(&client, "application_id = ?", clientID).Error; err != nil {
		if err == gorm.ErrRecordNotFound || client.ApplicationID == uuid.Nil {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "client not found")
		}
		return nil, meilingErrors.NewInternalServerError("failed to find client", err)
	}
	// A client whose application is gone is not usable.
	if client.Application == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "client not found")
	}

	return &client, nil
}

func findPermissionByID(permissionID string) (*database.Permission, error) {
	if permissionID == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "permission id is required")
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}

	var permission database.Permission
	if err := db.First(&permission, "id = ?", permissionID).Error; err != nil {
		if err == gorm.ErrRecordNotFound || permission.ID == uuid.Nil {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "permission not found")
		}
		return nil, meilingErrors.NewInternalServerError("failed to find permission", err)
	}

	return &permission, nil
}

func findPermissionByScope(scope string) (*database.Permission, error) {
	if scope == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "scope is required")
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}

	var permission database.Permission
	if err := db.First(&permission, "scope = ?", scope).Error; err != nil {
		if err == gorm.ErrRecordNotFound || permission.ID == uuid.Nil {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "permission not found")
		}
		return nil, meilingErrors.NewInternalServerError("failed to find permission", err)
	}

	return &permission, nil
}

func findConsentLogByID(consentLogID string) (*database.ApplicationConsentLog, error) {
	if consentLogID == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "consent log id is required")
	}

	db, err := getConsentLogDB()
	if err != nil {
		return nil, err
	}

	var consentLog database.ApplicationConsentLog
	if err := db.First(&consentLog, "id = ?", consentLogID).Error; err != nil {
		if err == gorm.ErrRecordNotFound || consentLog.ID == uuid.Nil {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "consent log not found")
		}
		return nil, meilingErrors.NewInternalServerError("failed to find consent log", err)
	}

	return &consentLog, nil
}

func findAuthenticatorsByIDs(ids []string) ([]database.UserAuthenticator, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}

	authenticators := make([]database.UserAuthenticator, 0, len(ids))
	if err := db.Where("id IN ?", ids).Find(&authenticators).Error; err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to find authenticators", err)
	}

	return authenticators, nil
}

func findAuthenticatorByIdentifierAndType(identifier string, validatorType string) (*database.UserAuthenticator, error) {
	db, err := getDB()
	if err != nil {
		return nil, err
	}

	var authenticator database.UserAuthenticator
	if err := db.First(&authenticator, "identifier = ? AND type = ?", identifier, validatorType).Error; err != nil {
		if err == gorm.ErrRecordNotFound || authenticator.ID == uuid.Nil {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "authenticator not found")
		}
		return nil, meilingErrors.NewInternalServerError("failed to find authenticator", err)
	}

	return &authenticator, nil
}

func saveUserWithAssociations(user *database.User) error {
	db, err := getUserDB()
	if err != nil {
		return err
	}

	if err := db.Session(&gorm.Session{FullSaveAssociations: true}).Updates(user).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to update user", err)
	}

	return nil
}
