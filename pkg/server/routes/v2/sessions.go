package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerSessionRoutes registers all session routes under /v2/sessions
func (r *V2Router) registerSessionRoutes(v2API huma.API) {
	cfg := r.app.Config()
	adminTokenMethod := cfg.AdminConfig.AdminTokenMethod

	sessionsAPI := huma.NewGroup(v2API, "/sessions")
	sessionsAPI.UseMiddleware(middleware.HumaValidateFrontendOrigins(cfg))

	ctrl := r.registry.GetSessionController()

	// Validate Session
	huma.Register(sessionsAPI, huma.Operation{
		OperationID: "validateSession",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Validate a session is valid",
		Description: "Validate that the provided session token is valid",
		Tags:        []string{"sessions"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleValidateSession)

	// Create Session
	huma.Register(sessionsAPI, huma.Operation{
		OperationID: "createSession",
		Method:      http.MethodPost,
		Path:        "/",
		Summary:     "Create or renew a session",
		Description: "Create a new session or renew an existing session token while keeping the same session id",
		Tags:        []string{"sessions"},
	}, ctrl.HandleCreateSession)

	adminSessionsAPI := huma.NewGroup(sessionsAPI, "/debug")
	adminSessionsAPI.UseMiddleware(middleware.HumaCheckSession(r.app))
	adminSessionsAPI.UseMiddleware(middleware.HumaCheckAdmin(r.app))

	// Get Session Debug (Admin only)
	huma.Register(adminSessionsAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "getSessionDebug",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get session debug information (Admin only)",
		Description: "Get session debug information for the specified or current session",
		Tags:        []string{"sessions"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleGetSessionDebug)
}
