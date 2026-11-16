package v2

import (
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// Huma Input/Output types

// ListPermissionsInput represents the input for listing permissions
type ListPermissionsInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.PageSizePaginationInput
	controllers.BypassPaginationInput
	Scope string `query:"scope" doc:"Scope String (Space Separated)" required:"false"`
	All   bool   `query:"all" doc:"Fetch all (including isPublic=false) if you are admin" required:"false"`
}

// ListPermissionsOutput represents the output for listing permissions
type ListPermissionsOutput struct {
	Body types.PaginatedPermissionSerialized
}

// CreatePermissionInput represents the input for creating a permission
type CreatePermissionInput struct {
	controllers.SessionAuthorizationHeaderInput
	Body types.AddPermissionRequest
}

// UpdatePermissionInput represents the input for updating a permission
type UpdatePermissionInput struct {
	controllers.SessionAuthorizationHeaderInput
	ID   string `query:"id" doc:"Permission ID" required:"true"`
	Body types.UpdatePermissionRequest
}

// DeletePermissionInput represents the input for deleting a permission
type DeletePermissionInput struct {
	controllers.SessionAuthorizationHeaderInput
	ID string `query:"id" doc:"Permission ID" required:"true"`
}
