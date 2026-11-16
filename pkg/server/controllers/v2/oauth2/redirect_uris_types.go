package oauth2

import (
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// GetRedirectURIsInput represents the input for getting redirect URIs
type GetRedirectURIsInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	controllers.OptionalUserIDQueryInput
}

// GetRedirectURIsOutput represents the output for getting redirect URIs
type GetRedirectURIsOutput struct {
	Body []types.ClientRedirectUriSerialized
}

// CreateRedirectURIInput represents the input for creating a redirect URI
type CreateRedirectURIInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	controllers.OptionalUserIDQueryInput
	Body types.AddRedirectUriRequest
}

// DeleteRedirectURIInput represents the input for deleting a redirect URI
type DeleteRedirectURIInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	controllers.OptionalUserIDQueryInput
	RedirectURIID string `query:"redirectUriId" doc:"Redirect Uri ID" required:"true"`
}

// LogoutSettingsInput names the application whose logout settings are read.
type LogoutSettingsInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	controllers.OptionalUserIDQueryInput
}

// SetLogoutSettingsInput replaces the application's logout settings.
type SetLogoutSettingsInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	controllers.OptionalUserIDQueryInput
	Body types.ClientLogoutSettings
}

// LogoutSettingsOutput is the application's logout settings.
type LogoutSettingsOutput struct {
	Body types.ClientLogoutSettings
}
