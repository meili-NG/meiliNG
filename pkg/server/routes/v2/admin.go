package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerAdminRoutes registers administrative meta-routes under /v2/admin.
//
// The group is guarded by CheckAdmin alone, without a preceding CheckSession.
// That is deliberate: a raw admin token (admin.adminTokens) is not a session token,
// so a session check would reject it before the admin check ever runs. This
// group is the canonical way for a client to ask "are these credentials admin?",
// for an admin token and an admin-audience M2M access token alike.
func (r *V2Router) registerAdminRoutes(v2API huma.API) {
	cfg := r.app.Config()
	adminTokenMethod := cfg.AdminConfig.AdminTokenMethod

	adminAPI := huma.NewGroup(v2API, "/admin")
	adminAPI.UseMiddleware(middleware.HumaValidateFrontendOrigins(cfg))
	adminAPI.UseMiddleware(middleware.HumaCheckAdmin(r.app))

	ctrl := r.registry.GetAdminController()

	// Admin probe: confirms the caller has admin privileges. Side-effect free.
	huma.Register(adminAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "adminProbe",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Probe admin authorization (Admin only)",
		Description: "Returns 200 when the caller is an admin, 401/403 otherwise. Accepts an admin token or an M2M access token for the admin audience, and names which one.",
		Tags:        []string{"admin"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleProbe)
}
