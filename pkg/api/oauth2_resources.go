package api

import (
	"slices"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"gorm.io/gorm"
)

func GetOAuth2ClientSecrets(clientID string) ([]types.ClientSecretSerialized, error) {
	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return nil, err
	}

	return utils.Map(client.Credentials, func(credential database.OauthCredential) types.ClientSecretSerialized {
		return types.ClientSecretSerialized{
			ID:           credential.ID.String(),
			ClientSecret: credential.Secret,
			Notes:        credential.Notes,
		}
	}), nil
}

func CreateOAuth2ClientSecret(cfg *config.MeilingConfig, clientID string, notes string) (types.ClientSecretSerialized, error) {
	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return types.ClientSecretSerialized{}, err
	}

	db, err := getDB()
	if err != nil {
		return types.ClientSecretSerialized{}, err
	}

	secretLength := config.OAuth2Config{}.GetClientSecretLength()
	if cfg != nil {
		secretLength = cfg.OAuth2Config.GetClientSecretLength()
	}

	credential := database.OauthCredential{
		OAuthCredentialFields: models.OAuthCredentialFields{
			ID:       uuid.New(),
			ClientID: client.ApplicationID,
			Secret:   utils.RandomString(secretLength),
			Notes:    notes,
		},
	}

	if err := db.Create(&credential).Error; err != nil {
		return types.ClientSecretSerialized{}, meilingErrors.NewInternalServerError("failed to create secret", err)
	}

	return types.ClientSecretSerialized{
		ID:           credential.ID.String(),
		ClientSecret: credential.Secret,
		Notes:        credential.Notes,
	}, nil
}

func DeleteOAuth2ClientSecret(clientID string, secretID string) error {
	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return err
	}
	if secretID == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid secret id")
	}

	target, found := utils.Find(client.Credentials, func(credential database.OauthCredential) bool {
		return credential.ID.String() == secretID
	})
	if !found {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "secret not found")
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	if err := db.Delete(&target).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to delete secret", err)
	}

	return nil
}

func GetOAuth2ClientRedirectURIs(clientID string) ([]types.ClientRedirectUriSerialized, error) {
	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return nil, err
	}

	return utils.Map(client.RedirectURIs, func(uri database.OauthRedirectURI) types.ClientRedirectUriSerialized {
		return types.ClientRedirectUriSerialized{
			ID:          uri.ID.String(),
			RedirectURI: uri.URI,
		}
	}), nil
}

func AddOAuth2ClientRedirectURI(clientID string, redirectURI string) error {
	if !validator.IsValidRedirectURI(redirectURI) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid redirect uri")
	}

	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return err
	}

	client.AddRedirectURI(redirectURI)
	return nil
}

func DeleteOAuth2ClientRedirectURI(clientID string, redirectURIID string) error {
	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return err
	}
	if redirectURIID == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "redirectUriId is required")
	}

	target, found := utils.Find(client.RedirectURIs, func(uri database.OauthRedirectURI) bool {
		return uri.ID.String() == redirectURIID
	})
	if !found {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "redirectUriId is not found")
	}

	db, err := getOAuth2DB()
	if err != nil {
		return err
	}

	if err := db.Delete(&target).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to delete redirect uri", err)
	}

	return nil
}

func GetOAuth2ClientAudiences(clientID string) ([]types.ClientAudienceSerialized, error) {
	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return nil, err
	}

	assigned := utils.Filter(client.Audiences, func(assignment database.OauthClientAudience) bool {
		return assignment.Audience != nil
	})

	return utils.Map(assigned, func(assignment database.OauthClientAudience) types.ClientAudienceSerialized {
		return types.ClientAudienceSerialized{
			ID:          assignment.ID.String(),
			AudienceID:  assignment.AudienceID.String(),
			Audience:    assignment.Audience.Audience,
			Description: assignment.Audience.Description,
		}
	}), nil
}

// AssignOAuth2ClientAudience grants a client one of the audiences registered on
// this instance. The audience must already exist: a client may not name a
// resource server Meiling does not know.
func AssignOAuth2ClientAudience(clientID string, audienceID string) (types.ClientAudienceSerialized, error) {
	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return types.ClientAudienceSerialized{}, err
	}

	audience, err := findOAuth2AudienceByID(audienceID)
	if err != nil {
		return types.ClientAudienceSerialized{}, err
	}

	if client.AllowsAudience(audience.Audience) {
		return types.ClientAudienceSerialized{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "audience is already assigned to this client")
	}

	db, err := getDB()
	if err != nil {
		return types.ClientAudienceSerialized{}, err
	}

	assignment := database.OauthClientAudience{
		OAuthClientAudienceFields: models.OAuthClientAudienceFields{
			ID:         uuid.New(),
			ClientID:   client.ApplicationID,
			AudienceID: audience.ID,
		},
	}
	if err := db.Create(&assignment).Error; err != nil {
		return types.ClientAudienceSerialized{}, meilingErrors.NewInternalServerError("failed to assign audience", err)
	}

	return types.ClientAudienceSerialized{
		ID:          assignment.ID.String(),
		AudienceID:  audience.ID.String(),
		Audience:    audience.Audience,
		Description: audience.Description,
	}, nil
}

// UnassignOAuth2ClientAudience revokes a client's access to an audience. The
// audience itself stays in the catalog. assignmentID is the assignment's own
// id, as returned by GetOAuth2ClientAudiences.
func UnassignOAuth2ClientAudience(clientID string, assignmentID string) error {
	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return err
	}
	if assignmentID == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "audienceId is required")
	}

	target, found := utils.Find(client.Audiences, func(assignment database.OauthClientAudience) bool {
		return assignment.ID.String() == assignmentID || assignment.AudienceID.String() == assignmentID
	})
	if !found {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "audience is not assigned to this client")
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	if err := db.Delete(&database.OauthClientAudience{}, "id = ?", target.ID).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to unassign audience", err)
	}

	return nil
}

// GetOAuth2ClientLogout returns the client's logout settings.
func GetOAuth2ClientLogout(clientID string) (types.ClientLogoutSettings, error) {
	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return types.ClientLogoutSettings{}, err
	}
	return types.ClientLogoutSettings{
		PostLogoutRedirectURIs: utils.Map(client.PostLogoutRedirectURIs, func(uri database.OauthPostLogoutRedirectURI) string { return uri.URI }),
		BackchannelLogoutURI:   client.BackchannelLogoutURI,
		FrontchannelLogoutURI:  client.FrontchannelLogoutURI,
	}, nil
}

// SetOAuth2ClientLogout replaces the client's logout settings.
func SetOAuth2ClientLogout(clientID string, settings types.ClientLogoutSettings) error {
	for _, uri := range settings.PostLogoutRedirectURIs {
		if !validLogoutURI(uri) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid post-logout redirect uri: "+uri)
		}
	}
	for _, uri := range []string{settings.BackchannelLogoutURI, settings.FrontchannelLogoutURI} {
		if uri != "" && !validLogoutURI(uri) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid logout uri: "+uri)
		}
	}

	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return err
	}
	db, err := getDB()
	if err != nil {
		return err
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("client_id = ?", client.ApplicationID).Delete(&database.OauthPostLogoutRedirectURI{}).Error; err != nil {
			return err
		}
		for _, uri := range slices.Compact(slices.Sorted(slices.Values(settings.PostLogoutRedirectURIs))) {
			if err := tx.Create(&database.OauthPostLogoutRedirectURI{OAuthPostLogoutRedirectURIFields: models.OAuthPostLogoutRedirectURIFields{
				ID: uuid.New(), URI: uri, ClientID: client.ApplicationID,
			}}).Error; err != nil {
				return err
			}
		}
		return tx.Model(&database.OauthClient{}).Where("application_id = ?", client.ApplicationID).Updates(map[string]any{
			"backchannel_logout_uri":  settings.BackchannelLogoutURI,
			"frontchannel_logout_uri": settings.FrontchannelLogoutURI,
		}).Error
	})
	if err != nil {
		return meilingErrors.NewInternalServerError("failed to save logout settings", err)
	}
	return nil
}
