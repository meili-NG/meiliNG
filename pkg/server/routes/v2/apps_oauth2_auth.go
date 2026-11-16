package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

// registerOAuth2ClientAuthRoutes registers OAuth2 client auth routes
func (r *V2Router) registerOAuth2ClientAuthRoutes(oauth2API huma.API) {
	authAPI := huma.NewGroup(oauth2API, "/auth")
	authCtrl := r.registry.GetOAuth2().GetAuthController()

	huma.Register(authAPI, huma.Operation{
		OperationID: "authEndpointCall",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Check if user consent is required for Approving oAuth2 Client",
		Description: "Check if user consent is required for Approving oAuth2 Client",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, authCtrl.HandleAuthEndpointCall)

	huma.Register(authAPI, huma.Operation{
		OperationID: "authorizeClient",
		Method:      http.MethodPost,
		Path:        "/",
		Summary:     "Authorize oAuth2 Client",
		Description: "Authorize oAuth2 Client",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, authCtrl.HandleAuthorizeClient)
}
