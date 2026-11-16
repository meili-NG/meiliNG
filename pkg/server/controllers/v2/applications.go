package v2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// ApplicationsController handles application-related business logic
type ApplicationsController struct {
	controllers.Base
}

// NewApplicationsController creates a new applications controller
func NewApplicationsController(a *app.Meiling) *ApplicationsController {
	return &ApplicationsController{Base: controllers.NewBase(a)}
}

func (c *ApplicationsController) HandleGetApplications(ctx context.Context, input *GetApplicationsInput) (*GetApplicationsOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	pagination, err := controllers.HTTPPagination(input.Page, input.Size, false, 10)
	if err != nil {
		return nil, err
	}

	result, err := api.ListApplicationsPaginated(&api.ListApplicationsRequest{
		Caller:     caller,
		Pagination: pagination,
		All:        input.All,
		Owned:      input.Owned,
		Authorized: input.Authorized,
		UserID:     input.UserID,
	})
	if err != nil {
		return nil, err
	}

	return &GetApplicationsOutput{Body: result}, nil
}

func (c *ApplicationsController) HandleCreateApplication(ctx context.Context, input *CreateApplicationInput) (*CreateApplicationOutput, error) {
	if err := validator.ValidatePayloadOrError(input.Body); err != nil {
		return nil, err
	}

	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	application, err := api.CreateApplication(&api.CreateApplicationRequest{
		Config:         c.Config(),
		Caller:         caller,
		UserID:         input.UserID,
		Name:           input.Body.Name,
		IsPublicClient: input.Body.IsPublicClient,
		RedirectURIs:   input.Body.RedirectURIs,
		Privacy:        input.Body.Privacy,
		Terms:          input.Body.Terms,
	})
	if err != nil {
		return nil, err
	}

	return &CreateApplicationOutput{
		Location: "/v2/apps/" + application.ID,
		Body:     application,
	}, nil
}

func (c *ApplicationsController) HandleGetApplication(ctx context.Context, input *GetApplicationInput) (*GetApplicationOutput, error) {
	caller, err := c.ResolveOptionalPrincipal(ctx, input.Authorization)
	if err != nil {
		return nil, err
	}

	application, err := api.GetApplication(input.AppID, caller)
	if err != nil {
		return nil, err
	}

	return &GetApplicationOutput{Body: application}, nil
}

func (c *ApplicationsController) HandleDeleteApplication(ctx context.Context, input *DeleteApplicationInput) (*types.BlankBody, error) {
	if err := api.DeleteApplication(input.AppID); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *ApplicationsController) HandleUpdateApplication(ctx context.Context, input *UpdateApplicationInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.UpdateApplication(input.AppID, &api.UpdateApplicationRequest{
		Caller:         caller,
		Name:           input.Body.Name,
		IsPublicClient: input.Body.IsPublicClient,
	}); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *ApplicationsController) HandleUnauthorizeApplication(ctx context.Context, input *UnauthorizeApplicationInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.UnauthorizeApplication(input.AppID, &api.UnauthorizeRequest{
		Caller: caller,
		UserID: input.UserID,
	}); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

// HandleGetPermissionLimit reads which permissions an application may request.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *ApplicationsController) HandleGetPermissionLimit(ctx context.Context, input *GetApplicationPermissionLimitInput) (*ApplicationPermissionLimitOutput, error) {
	limit, err := api.GetApplicationPermissionLimit(input.AppID)
	if err != nil {
		return nil, err
	}

	return &ApplicationPermissionLimitOutput{Body: limit}, nil
}

// HandleSetPermissionLimit replaces which permissions an application may request.
// NOTE: Admin authorization is enforced by middleware at the route level
func (c *ApplicationsController) HandleSetPermissionLimit(ctx context.Context, input *SetApplicationPermissionLimitInput) (*ApplicationPermissionLimitOutput, error) {
	limit, err := api.SetApplicationPermissionLimit(input.AppID, input.Body.Limited, input.Body.PermissionIDs)
	if err != nil {
		return nil, err
	}

	return &ApplicationPermissionLimitOutput{Body: limit}, nil
}
