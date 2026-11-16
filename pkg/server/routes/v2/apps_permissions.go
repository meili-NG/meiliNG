package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerApplicationPermissionsRoutes registers the routes that limit which
// permissions an application may request. They are admin-only: an application
// owner must not be able to widen what their own application can ask users for.
func (r *V2Router) registerApplicationPermissionsRoutes(appActionAPI huma.API) {
	adminTokenMethod := r.app.Config().AdminConfig.AdminTokenMethod

	permissionsAPI := huma.NewGroup(appActionAPI, "/permissions")
	permissionsAPI.UseMiddleware(middleware.HumaCheckAdmin(r.app))
	appCtrl := r.registry.GetApplicationsController()

	huma.Register(permissionsAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "getApplicationPermissions",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get the permissions an Application may request",
		Description: "While limited is false the application may request every permission. While it is true the application may only request the default permissions, the listed permissions and the ones they contain.",
		Tags:        []string{"applications"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), appCtrl.HandleGetPermissionLimit)

	huma.Register(permissionsAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "setApplicationPermissions",
		Method:      http.MethodPut,
		Path:        "/",
		Summary:     "Set the permissions an Application may request",
		Description: "Replace the limit as a whole. A listed permission also allows the permissions it contains, never its parent. limited with an empty list leaves the application the default permissions only.",
		Tags:        []string{"applications"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), appCtrl.HandleSetPermissionLimit)
}
