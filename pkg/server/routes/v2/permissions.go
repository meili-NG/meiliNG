package v2

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/metadata"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerPermissionRoutes registers all permission routes under /v2/permissions
func (r *V2Router) registerPermissionRoutes(v2API huma.API) {
	cfg := r.app.Config()

	permissions := huma.NewGroup(v2API, "/permissions")
	permissions.UseMiddleware(middleware.HumaValidateFrontendOrigins(cfg))
	permissions.UseMiddleware(middleware.HumaCheckSession(r.app))

	ctrl := r.registry.GetPermissionsController()

	adminPermissions := huma.NewGroup(permissions)
	adminPermissions.UseMiddleware(middleware.HumaCheckAdmin(r.app))

	r.registerPermissionCollectionRoutes(permissions, adminPermissions, ctrl)

	permissionMetadataAPI := huma.NewGroup(adminPermissions, "/metadata")
	permissionID := func(i *controllerv2.PermissionMetadataInput) string { return i.ID }
	permissionBodyID := func(i *controllerv2.PermissionMetadataBodyInput) string { return i.ID }
	permissionBody := func(i *controllerv2.PermissionMetadataBodyInput) map[string]any { return i.Body }
	registerMetadataRoutes(r, permissionMetadataAPI, "Permission", "permissions",
		controllerv2.GetMetadata(metadata.Permissions, permissionID),
		controllerv2.ChangeMetadata(metadata.Permissions, false, permissionBodyID, permissionBody),
		controllerv2.ChangeMetadata(metadata.Permissions, true, permissionBodyID, permissionBody))
}
