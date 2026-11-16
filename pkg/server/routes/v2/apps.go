package v2

import (
	"github.com/meili-NG/meiliNG/v2/pkg/metadata"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerApplicationRoutes registers the application routes under /v2/apps
func (r *V2Router) registerApplicationRoutes(v2API huma.API) {
	appCtrl := r.registry.GetApplicationsController()

	appsAPI := huma.NewGroup(v2API, "/apps")
	appsAPI.UseMiddleware(middleware.HumaCheckSession(r.app))

	huma.Register(appsAPI, huma.Operation{
		OperationID: "getApplications",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get all Applications",
		Description: "Get all Applications",
		Tags:        []string{"applications"},
		Security:    serverHelpers.SessionSecurity(),
	}, appCtrl.HandleGetApplications)

	huma.Register(appsAPI, huma.Operation{
		OperationID:   "createApplication",
		Method:        http.MethodPost,
		Path:          "/",
		Summary:       "Create a new Application",
		Description:   "Create a new Application together with its OAuth2 client",
		Tags:          []string{"applications"},
		Security:      serverHelpers.SessionSecurity(),
		DefaultStatus: http.StatusCreated,
	}, appCtrl.HandleCreateApplication)

	appActionAPI := huma.NewGroup(appsAPI, "/{app_id}")
	appActionAPI.UseMiddleware(middleware.HumaFetchApplication())

	huma.Register(appActionAPI, huma.Operation{
		OperationID: "getApplication",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get an Application",
		Description: "Get an Application",
		Tags:        []string{"applications"},
		Security:    serverHelpers.SessionSecurity(),
	}, appCtrl.HandleGetApplication)

	huma.Register(appActionAPI, huma.Operation{
		OperationID: "unauthorizeApplication",
		Method:      http.MethodPost,
		Path:        "/unauthorize",
		Summary:     "Unauthorize an Application",
		Description: "Revoke what a user granted to an Application",
		Tags:        []string{"applications"},
		Security:    serverHelpers.SessionSecurity(),
	}, appCtrl.HandleUnauthorizeApplication)

	appOwnerAPI := huma.NewGroup(appActionAPI)
	appOwnerAPI.UseMiddleware(middleware.HumaCheckApplicationOwnership())

	huma.Register(appOwnerAPI, huma.Operation{
		OperationID: "deleteApplication",
		Method:      http.MethodDelete,
		Path:        "/",
		Summary:     "Delete an Application",
		Description: "Delete an Application together with its OAuth2 client, redirect URIs, secrets, audience assignments, allowed permissions and consent logs",
		Tags:        []string{"applications"},
		Security:    serverHelpers.SessionSecurity(),
	}, appCtrl.HandleDeleteApplication)

	huma.Register(appOwnerAPI, huma.Operation{
		OperationID: "updateApplication",
		Method:      http.MethodPut,
		Path:        "/",
		Summary:     "Update an Application",
		Description: "Update an Application",
		Tags:        []string{"applications"},
		Security:    serverHelpers.SessionSecurity(),
	}, appCtrl.HandleUpdateApplication)

	r.registerApplicationPermissionsRoutes(appActionAPI)

	appMetadataAPI := huma.NewGroup(appActionAPI, "/metadata")
	appMetadataAPI.UseMiddleware(middleware.HumaCheckAdmin(r.app))
	appID := func(i *controllerv2.AppMetadataInput) string { return i.AppID }
	appBodyID := func(i *controllerv2.AppMetadataBodyInput) string { return i.AppID }
	appBody := func(i *controllerv2.AppMetadataBodyInput) map[string]any { return i.Body }
	registerMetadataRoutes(r, appMetadataAPI, "Application", "applications",
		controllerv2.GetMetadata(metadata.Applications, appID),
		controllerv2.ChangeMetadata(metadata.Applications, false, appBodyID, appBody),
		controllerv2.ChangeMetadata(metadata.Applications, true, appBodyID, appBody))

	oauth2API := huma.NewGroup(appActionAPI, "/oauth2")
	r.registerOAuth2ClientSecretsRoutes(oauth2API)
	r.registerOAuth2ClientRedirectURIsRoutes(oauth2API)
	r.registerOAuth2ClientLogoutRoutes(oauth2API)
	r.registerOAuth2ClientAudiencesRoutes(oauth2API)
	r.registerOAuth2ClientAuthRoutes(oauth2API)
}
