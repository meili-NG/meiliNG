package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

func (r *V2Router) registerPermissionCollectionRoutes(permissionsAPI, adminPermissionsAPI huma.API, ctrl *controllerv2.PermissionsController) {
	adminTokenMethod := r.app.Config().AdminConfig.AdminTokenMethod

	huma.Register(permissionsAPI, huma.Operation{
		OperationID: "listPermissions",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "List Permissions",
		Description: "List Permissions",
		Tags:        []string{"permissions"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleListPermissions)

	huma.Register(adminPermissionsAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID:   "createPermission",
		Method:        http.MethodPost,
		Path:          "/",
		Summary:       "Create Permission (Admin only)",
		Description:   "Create Permission (Admin only)",
		Tags:          []string{"permissions"},
		Security:      serverHelpers.SessionSecurity(),
		DefaultStatus: http.StatusCreated,
	}, adminTokenMethod), ctrl.HandleCreatePermission)

	huma.Register(adminPermissionsAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "updatePermission",
		Method:      http.MethodPut,
		Path:        "/",
		Summary:     "Update Permission (Admin only)",
		Description: "Replace the parent, visibility and message of a permission. The scope cannot be changed.",
		Tags:        []string{"permissions"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleUpdatePermission)

	huma.Register(adminPermissionsAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "deletePermission",
		Method:      http.MethodDelete,
		Path:        "/",
		Summary:     "Delete Permission (Admin only)",
		Description: "Delete Permission (Admin only)",
		Tags:        []string{"permissions"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleDeletePermission)
}
