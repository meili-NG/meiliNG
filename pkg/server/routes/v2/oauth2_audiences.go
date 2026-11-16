package v2

import (
	"github.com/meili-NG/meiliNG/v2/pkg/metadata"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerOAuth2AudienceRoutes registers the catalog of audiences this
// instance knows about. An audience is a resource server, so it is registered
// once here and then assigned to the clients that may request it. Admin-only
// for the same reason the assignment is: the audience decides which resource
// server, and through the admin token audience Meiling itself, accepts a
// machine token.
func (r *V2Router) registerOAuth2AudienceRoutes(oauth2API huma.API) {
	adminTokenMethod := r.app.Config().AdminConfig.AdminTokenMethod

	audiencesAPI := huma.NewGroup(oauth2API, "/audiences")
	audiencesAPI.UseMiddleware(middleware.HumaCheckAdmin(r.app))
	ctrl := r.registry.GetOAuth2().GetAudiencesController()

	huma.Register(audiencesAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "listOAuth2Audiences",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "List OAuth2 Audiences (Admin only)",
		Description: "List every audience registered on this instance, with how many clients each is assigned to.",
		Tags:        []string{"oauth2_audiences"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleListCatalog)

	huma.Register(audiencesAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID:   "createOAuth2Audience",
		Method:        http.MethodPost,
		Path:          "/",
		Summary:       "Register an OAuth2 Audience (Admin only)",
		Description:   "Register a resource server audience so clients can be assigned to it.",
		Tags:          []string{"oauth2_audiences"},
		Security:      serverHelpers.SessionSecurity(),
		DefaultStatus: http.StatusCreated,
	}, adminTokenMethod), ctrl.HandleCreateCatalogEntry)

	audienceActionAPI := huma.NewGroup(audiencesAPI, "/{audience_id}")

	audienceMetadataAPI := huma.NewGroup(audienceActionAPI, "/metadata")
	audienceID := func(i *controllerv2.AudienceMetadataInput) string { return i.AudienceID }
	audienceBodyID := func(i *controllerv2.AudienceMetadataBodyInput) string { return i.AudienceID }
	audienceBody := func(i *controllerv2.AudienceMetadataBodyInput) map[string]any { return i.Body }
	registerMetadataRoutes(r, audienceMetadataAPI, "Audience", "oauth2_audiences",
		controllerv2.GetMetadata(metadata.Audiences, audienceID),
		controllerv2.ChangeMetadata(metadata.Audiences, false, audienceBodyID, audienceBody),
		controllerv2.ChangeMetadata(metadata.Audiences, true, audienceBodyID, audienceBody))

	huma.Register(audienceActionAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "getOAuth2Audience",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get an OAuth2 Audience (Admin only)",
		Description: "Get a registered audience.",
		Tags:        []string{"oauth2_audiences"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleGetCatalogEntry)

	huma.Register(audienceActionAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "updateOAuth2Audience",
		Method:      http.MethodPut,
		Path:        "/",
		Summary:     "Update an OAuth2 Audience (Admin only)",
		Description: "Edit a registered audience's description. The audience value itself is immutable: tokens are issued against it.",
		Tags:        []string{"oauth2_audiences"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleUpdateCatalogEntry)

	huma.Register(audienceActionAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "deleteOAuth2Audience",
		Method:      http.MethodDelete,
		Path:        "/",
		Summary:     "Delete an OAuth2 Audience (Admin only)",
		Description: "Remove a registered audience. Refused while clients are still assigned to it.",
		Tags:        []string{"oauth2_audiences"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleDeleteCatalogEntry)

	huma.Register(audienceActionAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "listOAuth2AudienceClients",
		Method:      http.MethodGet,
		Path:        "/clients",
		Summary:     "List Clients of an OAuth2 Audience (Admin only)",
		Description: "List the clients this audience is assigned to.",
		Tags:        []string{"oauth2_audiences"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleListCatalogEntryClients)
}
