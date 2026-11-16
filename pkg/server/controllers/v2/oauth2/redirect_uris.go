package oauth2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// RedirectURIsController handles OAuth2 client redirect URI operations
type RedirectURIsController struct {
	controllers.Base
}

// NewRedirectURIsController creates a new OAuth2 redirect URIs controller
func NewRedirectURIsController(a *app.Meiling) *RedirectURIsController {
	return &RedirectURIsController{Base: controllers.NewBase(a)}
}

// Handler methods

// HandleGetRedirectURIs handles getting redirect URIs
// NOTE: Ownership validation is enforced by middleware at the route level
func (c *RedirectURIsController) HandleGetRedirectURIs(ctx context.Context, input *GetRedirectURIsInput) (*GetRedirectURIsOutput, error) {
	redirectURIs, err := api.GetOAuth2ClientRedirectURIs(input.AppID)
	if err != nil {
		return nil, err
	}

	return &GetRedirectURIsOutput{Body: redirectURIs}, nil
}

// HandleCreateRedirectURI handles creating a redirect URI
// NOTE: Ownership validation is enforced by middleware at the route level
func (c *RedirectURIsController) HandleCreateRedirectURI(ctx context.Context, input *CreateRedirectURIInput) (*types.BlankBody, error) {
	body := input.Body

	if err := validator.ValidatePayloadOrError(body); err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
	}

	if !validator.IsValidRedirectURI(body.RedirectURI) {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid redirect uri")
	}

	if err := api.AddOAuth2ClientRedirectURI(input.AppID, body.RedirectURI); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

// HandleDeleteRedirectURI handles deleting a redirect URI
// NOTE: Ownership validation is enforced by middleware at the route level
func (c *RedirectURIsController) HandleDeleteRedirectURI(ctx context.Context, input *DeleteRedirectURIInput) (*types.BlankBody, error) {
	if err := api.DeleteOAuth2ClientRedirectURI(input.AppID, input.RedirectURIID); err != nil {
		return nil, err
	}
	return &types.BlankBody{}, nil
}

// HandleGetLogoutSettings returns the application's logout settings.
// NOTE: Ownership validation is enforced by middleware at the route level
func (c *RedirectURIsController) HandleGetLogoutSettings(ctx context.Context, input *LogoutSettingsInput) (*LogoutSettingsOutput, error) {
	settings, err := api.GetOAuth2ClientLogout(input.AppID)
	if err != nil {
		return nil, err
	}
	return &LogoutSettingsOutput{Body: settings}, nil
}

// HandleSetLogoutSettings replaces the application's logout settings.
// NOTE: Ownership validation is enforced by middleware at the route level
func (c *RedirectURIsController) HandleSetLogoutSettings(ctx context.Context, input *SetLogoutSettingsInput) (*LogoutSettingsOutput, error) {
	if err := api.SetOAuth2ClientLogout(input.AppID, input.Body); err != nil {
		return nil, err
	}
	settings, err := api.GetOAuth2ClientLogout(input.AppID)
	if err != nil {
		return nil, err
	}
	return &LogoutSettingsOutput{Body: settings}, nil
}
