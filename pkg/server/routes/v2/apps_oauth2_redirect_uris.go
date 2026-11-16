package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerOAuth2ClientRedirectURIsRoutes registers OAuth2 client redirect URI routes
func (r *V2Router) registerOAuth2ClientRedirectURIsRoutes(oauth2API huma.API) {
	redirectURIsAPI := huma.NewGroup(oauth2API, "/redirect_uris")
	redirectURIsAPI.UseMiddleware(middleware.HumaValidateApplicationOwnership("query"))
	redirectURIsCtrl := r.registry.GetOAuth2().GetRedirectURIsController()

	huma.Register(redirectURIsAPI, huma.Operation{
		OperationID: "getOAuth2ClientRedirectUris",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get all OAuth2 Client Redirect Uris",
		Description: "Get all OAuth2 Client Redirect Uris",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, redirectURIsCtrl.HandleGetRedirectURIs)

	huma.Register(redirectURIsAPI, huma.Operation{
		OperationID: "createOAuth2ClientRedirectUri",
		Method:      http.MethodPost,
		Path:        "/",
		Summary:     "Create a OAuth2 Client Redirect Uri",
		Description: "Create a OAuth2 Client Redirect Uri",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, redirectURIsCtrl.HandleCreateRedirectURI)

	huma.Register(redirectURIsAPI, huma.Operation{
		OperationID: "deleteOAuth2ClientRedirectUri",
		Method:      http.MethodDelete,
		Path:        "/",
		Summary:     "Delete a OAuth2 Client Redirect Uri",
		Description: "Delete a OAuth2 Client Redirect Uri",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, redirectURIsCtrl.HandleDeleteRedirectURI)
}
