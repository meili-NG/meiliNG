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

// AudiencesController handles the audiences registered on this instance and
// their assignment to OAuth2 clients for the client_credentials grant.
type AudiencesController struct {
	controllers.Base
}

// NewAudiencesController creates a new OAuth2 audiences controller
func NewAudiencesController(a *app.Meiling) *AudiencesController {
	return &AudiencesController{Base: controllers.NewBase(a)}
}

// HandleListCatalog lists every audience registered on this instance.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *AudiencesController) HandleListCatalog(ctx context.Context, input *ListAudienceCatalogInput) (*ListAudienceCatalogOutput, error) {
	audiences, err := api.ListOAuth2Audiences()
	if err != nil {
		return nil, err
	}

	return &ListAudienceCatalogOutput{Body: audiences}, nil
}

// HandleGetCatalogEntry reads one registered audience.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *AudiencesController) HandleGetCatalogEntry(ctx context.Context, input *GetAudienceInput) (*AudienceOutput, error) {
	audience, err := api.GetOAuth2Audience(input.AudienceID)
	if err != nil {
		return nil, err
	}

	return &AudienceOutput{Body: audience}, nil
}

// HandleCreateCatalogEntry registers an audience on this instance.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *AudiencesController) HandleCreateCatalogEntry(ctx context.Context, input *CreateAudienceCatalogInput) (*AudienceOutput, error) {
	if err := validator.ValidatePayloadOrError(input.Body); err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
	}

	audience, err := api.CreateOAuth2Audience(input.Body.Audience, input.Body.Description)
	if err != nil {
		return nil, err
	}

	return &AudienceOutput{Body: audience}, nil
}

// HandleUpdateCatalogEntry edits a registered audience's description.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *AudiencesController) HandleUpdateCatalogEntry(ctx context.Context, input *UpdateAudienceCatalogInput) (*AudienceOutput, error) {
	audience, err := api.UpdateOAuth2Audience(input.AudienceID, input.Body.Description)
	if err != nil {
		return nil, err
	}

	return &AudienceOutput{Body: audience}, nil
}

// HandleDeleteCatalogEntry removes a registered audience.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *AudiencesController) HandleDeleteCatalogEntry(ctx context.Context, input *DeleteAudienceCatalogInput) (*types.BlankBody, error) {
	if err := api.DeleteOAuth2Audience(input.AudienceID); err != nil {
		return nil, err
	}
	return &types.BlankBody{}, nil
}

// HandleListCatalogEntryClients lists the clients an audience is assigned to.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *AudiencesController) HandleListCatalogEntryClients(ctx context.Context, input *GetAudienceInput) (*ListAudienceClientsOutput, error) {
	clients, err := api.ListOAuth2AudienceClients(input.AudienceID)
	if err != nil {
		return nil, err
	}

	return &ListAudienceClientsOutput{Body: clients}, nil
}

// HandleGetAudiences lists the audiences assigned to a client.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *AudiencesController) HandleGetAudiences(ctx context.Context, input *GetAudiencesInput) (*GetAudiencesOutput, error) {
	audiences, err := api.GetOAuth2ClientAudiences(input.AppID)
	if err != nil {
		return nil, err
	}

	return &GetAudiencesOutput{Body: audiences}, nil
}

// HandleAssignAudience grants a client one of the registered audiences.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *AudiencesController) HandleAssignAudience(ctx context.Context, input *AssignAudienceInput) (*AssignAudienceOutput, error) {
	if err := validator.ValidatePayloadOrError(input.Body); err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
	}

	audience, err := api.AssignOAuth2ClientAudience(input.AppID, input.Body.AudienceID)
	if err != nil {
		return nil, err
	}

	return &AssignAudienceOutput{Body: audience}, nil
}

// HandleUnassignAudience revokes a client's access to an audience.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *AudiencesController) HandleUnassignAudience(ctx context.Context, input *UnassignAudienceInput) (*types.BlankBody, error) {
	if err := api.UnassignOAuth2ClientAudience(input.AppID, input.AudienceID); err != nil {
		return nil, err
	}
	return &types.BlankBody{}, nil
}
