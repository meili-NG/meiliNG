package oauth2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// SecretsController handles OAuth2 client secrets operations
type SecretsController struct {
	controllers.Base
}

// NewSecretsController creates a new OAuth2 secrets controller
func NewSecretsController(a *app.Meiling) *SecretsController {
	return &SecretsController{Base: controllers.NewBase(a)}
}

// Handler methods

// HandleGetSecrets handles getting client secrets
// NOTE: Ownership validation is enforced by middleware at the route level
func (c *SecretsController) HandleGetSecrets(ctx context.Context, input *GetSecretsInput) (*GetSecretsOutput, error) {
	secrets, err := api.GetOAuth2ClientSecrets(input.AppID)
	if err != nil {
		return nil, err
	}

	return &GetSecretsOutput{Body: secrets}, nil
}

// HandleCreateSecret handles creating a client secret
// NOTE: Ownership validation is enforced by middleware at the route level
func (c *SecretsController) HandleCreateSecret(ctx context.Context, input *CreateSecretInput) (*CreateSecretOutput, error) {
	secret, err := api.CreateOAuth2ClientSecret(c.Config(), input.AppID, input.Body.Notes)
	if err != nil {
		return nil, err
	}

	return &CreateSecretOutput{
		Body: secret,
	}, nil
}

// HandleDeleteSecret handles deleting a client secret
// NOTE: Ownership validation is enforced by middleware at the route level
func (c *SecretsController) HandleDeleteSecret(ctx context.Context, input *DeleteSecretInput) (*types.BlankBody, error) {
	if err := api.DeleteOAuth2ClientSecret(input.AppID, input.SecretID); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}
