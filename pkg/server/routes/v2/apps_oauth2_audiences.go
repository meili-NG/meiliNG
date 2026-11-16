package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerOAuth2ClientAudiencesRoutes registers the routes that assign
// registered audiences to a client for the client_credentials grant. They are
// admin-only: an application owner must not be able to grant their own client
// access to another resource server, or to Meiling through the admin token
// audience.
func (r *V2Router) registerOAuth2ClientAudiencesRoutes(oauth2API huma.API) {
	adminTokenMethod := r.app.Config().AdminConfig.AdminTokenMethod

	audiencesAPI := huma.NewGroup(oauth2API, "/audiences")
	audiencesAPI.UseMiddleware(middleware.HumaCheckAdmin(r.app))
	audiencesCtrl := r.registry.GetOAuth2().GetAudiencesController()

	huma.Register(audiencesAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "getOAuth2ClientAudiences",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get all OAuth2 Client Audiences",
		Description: "List the audiences assigned to the client, which are the ones it may request with the client_credentials grant.",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), audiencesCtrl.HandleGetAudiences)

	huma.Register(audiencesAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID:   "assignOAuth2ClientAudience",
		Method:        http.MethodPost,
		Path:          "/",
		Summary:       "Assign an OAuth2 Audience to a Client",
		Description:   "Grant the client one of the audiences registered on this instance. Register it first through /v2/oauth2/audiences/.",
		Tags:          []string{"oauth2_clients"},
		Security:      serverHelpers.SessionSecurity(),
		DefaultStatus: http.StatusCreated,
	}, adminTokenMethod), audiencesCtrl.HandleAssignAudience)

	huma.Register(audiencesAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "unassignOAuth2ClientAudience",
		Method:      http.MethodDelete,
		Path:        "/",
		Summary:     "Unassign an OAuth2 Audience from a Client",
		Description: "Stop the client from requesting this audience. The audience stays registered on this instance.",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), audiencesCtrl.HandleUnassignAudience)
}
