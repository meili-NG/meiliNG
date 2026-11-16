package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerOAuth2ClientLogoutRoutes registers an application's OpenID Connect
// logout settings: post-logout redirect URIs and back- and front-channel
// logout URIs.
func (r *V2Router) registerOAuth2ClientLogoutRoutes(oauth2API huma.API) {
	logoutAPI := huma.NewGroup(oauth2API, "/logout")
	logoutAPI.UseMiddleware(middleware.HumaValidateApplicationOwnership("query"))
	ctrl := r.registry.GetOAuth2().GetRedirectURIsController()

	huma.Register(logoutAPI, huma.Operation{
		OperationID: "getOAuth2ClientLogout",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get an application's logout settings",
		Description: "Post-logout redirect URIs and back- and front-channel logout URIs",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetLogoutSettings)

	huma.Register(logoutAPI, huma.Operation{
		OperationID: "setOAuth2ClientLogout",
		Method:      http.MethodPut,
		Path:        "/",
		Summary:     "Replace an application's logout settings",
		Description: "Replaces the post-logout redirect URIs and the back- and front-channel logout URIs. An empty URI turns that logout off",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleSetLogoutSettings)
}
