package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerOAuth2ClientSecretsRoutes registers OAuth2 client secrets routes
func (r *V2Router) registerOAuth2ClientSecretsRoutes(oauth2API huma.API) {
	secretsAPI := huma.NewGroup(oauth2API, "/secrets")
	secretsAPI.UseMiddleware(middleware.HumaValidateApplicationOwnership("query"))
	secretsCtrl := r.registry.GetOAuth2().GetSecretsController()

	huma.Register(secretsAPI, huma.Operation{
		OperationID: "getOAuth2ClientSecrets",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get OAuth2 Client Secrets",
		Description: "Get OAuth2 Client Secrets",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, secretsCtrl.HandleGetSecrets)

	huma.Register(secretsAPI, huma.Operation{
		OperationID: "createOAuth2ClientSecret",
		Method:      http.MethodPost,
		Path:        "/",
		Summary:     "Create OAuth2 Client Secret",
		Description: "Create OAuth2 Client Secret",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, secretsCtrl.HandleCreateSecret)

	huma.Register(secretsAPI, huma.Operation{
		OperationID: "deleteOAuth2ClientSecret",
		Method:      http.MethodDelete,
		Path:        "/",
		Summary:     "Delete OAuth2 Client Secret",
		Description: "Delete OAuth2 Client Secret",
		Tags:        []string{"oauth2_clients"},
		Security:    serverHelpers.SessionSecurity(),
	}, secretsCtrl.HandleDeleteSecret)
}
