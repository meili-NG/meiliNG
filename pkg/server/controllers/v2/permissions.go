package v2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// PermissionsController handles permission-related operations
type PermissionsController struct {
	controllers.Base
}

// NewPermissionsController creates a new permissions controller
func NewPermissionsController(a *app.Meiling) *PermissionsController {
	return &PermissionsController{Base: controllers.NewBase(a)}
}

// Handler methods

// HandleListPermissions lists permissions
func (c *PermissionsController) HandleListPermissions(ctx context.Context, input *ListPermissionsInput) (*ListPermissionsOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	pagination, err := controllers.HTTPPagination(input.Page, input.Size, input.Bypass, 20)
	if err != nil {
		return nil, err
	}

	result, err := api.ListPermissionsPaginated(&api.ListPermissionsRequest{
		Caller:     caller,
		Pagination: pagination,
		All:        input.All,
		Scope:      input.Scope,
	})
	if err != nil {
		return nil, err
	}

	return &ListPermissionsOutput{Body: result}, nil
}

// HandleCreatePermission creates a permission
// NOTE: Admin check is enforced by middleware at the route level
func (c *PermissionsController) HandleCreatePermission(ctx context.Context, input *CreatePermissionInput) (*types.BlankBody, error) {
	body := input.Body
	if err := validator.ValidatePayloadOrError(body); err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
	}

	if err := api.CreatePermission(&api.CreatePermissionRequest{
		Scope:     body.Scope,
		IsPublic:  body.IsPublic,
		IsDefault: body.IsDefault,
		ParentID:  body.ParentID,
		Message:   body.Message,
	}); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

// HandleUpdatePermission replaces the mutable fields of a permission
// NOTE: Admin check is enforced by middleware at the route level
func (c *PermissionsController) HandleUpdatePermission(ctx context.Context, input *UpdatePermissionInput) (*types.BlankBody, error) {
	if err := api.UpdatePermission(&api.UpdatePermissionRequest{
		ID:        input.ID,
		ParentID:  input.Body.ParentID,
		IsPublic:  input.Body.IsPublic,
		IsDefault: input.Body.IsDefault,
		Message:   input.Body.Message,
	}); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

// HandleDeletePermission deletes a permission
// NOTE: Admin check is enforced by middleware at the route level
func (c *PermissionsController) HandleDeletePermission(ctx context.Context, input *DeletePermissionInput) (*types.BlankBody, error) {
	if input.ID == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "id is required")
	}

	if err := api.DeletePermission(input.ID); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}
