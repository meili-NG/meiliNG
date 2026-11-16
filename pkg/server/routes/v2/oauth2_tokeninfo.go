package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	oauth2ctrl "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2/oauth2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

// registerOAuth2TokenInfoRoutes registers token info routes
func (r *V2Router) registerOAuth2TokenInfoRoutes(oauth2API huma.API) {
	tokenInfoCtrl := r.registry.GetOAuth2().GetTokenInfoController()

	huma.Register(oauth2API, huma.Operation{
		OperationID: "oauth2TokenInfoGet",
		Method:      http.MethodGet,
		Path:        "/tokeninfo",
		Summary:     "Get token information",
		Description: "Get token information",
		Tags:        []string{"oauth2"},
	}, tokenInfoCtrl.HandleTokenInfoGet)

	huma.Register(oauth2API, huma.Operation{
		OperationID: "oauth2TokenInfoPost",
		Method:      http.MethodPost,
		Path:        "/tokeninfo",
		Summary:     "Get token information",
		Description: "Get token information",
		Tags:        []string{"oauth2"},
		RequestBody: serverHelpers.RequestBodyWithJSONAndForm[oauth2ctrl.TokenInfoPostRequest](oauth2API, false, "OAuth2 token info request"),
	}, tokenInfoCtrl.HandleTokenInfoPost)

	huma.Register(oauth2API, huma.Operation{
		OperationID: "oauth2UserInfoGet",
		Method:      http.MethodGet,
		Path:        "/userinfo",
		Summary:     "Get user information",
		Description: "Get user information",
		Tags:        []string{"oauth2"},
		Security:    serverHelpers.OAuth2Security(),
	}, tokenInfoCtrl.HandleUserInfoGet)

	huma.Register(oauth2API, huma.Operation{
		OperationID: "oauth2UserInfoPost",
		Method:      http.MethodPost,
		Path:        "/userinfo",
		Summary:     "Get user information",
		Description: "Get user information",
		Tags:        []string{"oauth2"},
		Security:    serverHelpers.OAuth2Security(),
		RequestBody: serverHelpers.RequestBodyWithJSONAndForm[oauth2ctrl.UserInfoPostRequest](oauth2API, false, "OAuth2 user info request"),
	}, tokenInfoCtrl.HandleUserInfoPost)
}
