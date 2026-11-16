package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	oauth2ctrl "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2/oauth2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	middleware "github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerOAuth2CoreRoutes registers core OAuth2 routes (auth, token, revoke)
func (r *V2Router) registerOAuth2CoreRoutes(oauth2API huma.API) {
	coreCtrl := r.registry.GetOAuth2().GetCoreController()
	authCtrl := r.registry.GetOAuth2().GetAuthController()

	huma.Register(oauth2API, huma.Operation{
		OperationID:   "oauth2AuthRedirect",
		Method:        http.MethodGet,
		Path:          "/auth",
		Summary:       "OAuth2 Authorization Endpoint",
		Description:   "Redirects OAuth2 Standard Authorization Request to the frontend",
		Tags:          []string{"oauth2"},
		DefaultStatus: http.StatusTemporaryRedirect,
	}, coreCtrl.HandleAuthRedirect)

	huma.Register(oauth2API, huma.Operation{
		OperationID:   "oauth2AuthRedirectPost",
		Method:        http.MethodPost,
		Path:          "/auth",
		Summary:       "OAuth2 Authorization Endpoint",
		Description:   "Accepts a form-encoded OAuth2/OpenID Connect authorization request and redirects to the frontend",
		Tags:          []string{"oauth2"},
		DefaultStatus: http.StatusTemporaryRedirect,
		RequestBody:   serverHelpers.RequestBodyWithForm[oauth2ctrl.AuthRedirectPostRequest](oauth2API, true, "OAuth2 authorization request"),
	}, coreCtrl.HandleAuthRedirectPost)

	huma.Register(oauth2API, huma.Operation{
		OperationID:   "oidcEndSession",
		Method:        http.MethodGet,
		Path:          "/logout",
		Summary:       "OpenID Connect RP-Initiated Logout",
		Description:   "Checks the logout request and redirects to the frontend, which asks the user to confirm",
		Tags:          []string{"oauth2"},
		DefaultStatus: http.StatusFound,
	}, coreCtrl.HandleEndSession)

	huma.Register(oauth2API, huma.Operation{
		OperationID:   "oidcEndSessionPost",
		Method:        http.MethodPost,
		Path:          "/logout",
		Summary:       "OpenID Connect RP-Initiated Logout",
		Description:   "Form-encoded logout request; see the GET form",
		Tags:          []string{"oauth2"},
		DefaultStatus: http.StatusFound,
		RequestBody:   serverHelpers.RequestBodyWithForm[oauth2ctrl.EndSessionRequest](oauth2API, true, "OpenID Connect logout request"),
	}, coreCtrl.HandleEndSessionPost)

	endSessionAPI := huma.NewGroup(oauth2API)
	endSessionAPI.UseMiddleware(middleware.HumaCheckSession(r.app))
	huma.Register(endSessionAPI, huma.Operation{
		OperationID: "oidcConfirmEndSession",
		Method:      http.MethodPost,
		Path:        "/logout/confirm",
		Summary:     "Confirm an RP-Initiated Logout",
		Description: "Signs the user out of the session, tells the applications they signed into through it, and answers where the browser goes next",
		Tags:        []string{"oauth2"},
		Security:    serverHelpers.SessionSecurity(),
	}, authCtrl.HandleConfirmEndSession)

	huma.Register(oauth2API, huma.Operation{
		OperationID: "oauth2Token",
		Method:      http.MethodPost,
		Path:        "/token",
		Summary:     "OAuth2 Token Endpoint",
		Description: "Exchanges OAuth2 Standard Authorization Code to Access Token",
		Tags:        []string{"oauth2"},
		RequestBody: serverHelpers.RequestBodyWithJSONAndForm[types.TokenRequest](oauth2API, true, "OAuth2 token request"),
	}, coreCtrl.HandleTokenExchange)

	huma.Register(oauth2API, huma.Operation{
		OperationID: "oauth2DeviceAuthorization",
		Method:      http.MethodPost,
		Path:        "/device",
		Summary:     "OAuth2 Device Authorization Endpoint",
		Description: "Starts an OAuth2 device authorization flow",
		Tags:        []string{"oauth2"},
		RequestBody: serverHelpers.RequestBodyWithJSONAndForm[types.DeviceAuthorizationRequest](oauth2API, true, "OAuth2 device authorization request"),
	}, coreCtrl.HandleDeviceAuthorization)

	deviceAuthorizeAPI := huma.NewGroup(oauth2API)
	deviceAuthorizeAPI.UseMiddleware(middleware.HumaCheckSession(r.app))

	huma.Register(deviceAuthorizeAPI, huma.Operation{
		OperationID: "oauth2AuthorizeDeviceCode",
		Method:      http.MethodPost,
		Path:        "/device/authorize",
		Summary:     "Authorize OAuth2 Device Code",
		Description: "Approves or denies an OAuth2 device authorization request",
		Tags:        []string{"oauth2"},
		Security:    serverHelpers.SessionSecurity(),
		RequestBody: serverHelpers.RequestBodyWithJSONAndForm[types.DeviceAuthorizeRequest](oauth2API, true, "OAuth2 device authorization approval request"),
	}, authCtrl.HandleAuthorizeDeviceCode)

	huma.Register(oauth2API, huma.Operation{
		OperationID: "oauth2IntrospectToken",
		Method:      http.MethodPost,
		Path:        "/introspect",
		Summary:     "OAuth2 Token Introspection",
		Description: "RFC 7662 introspection. A confidential client sees its own tokens as active; a client the client policy trusts sees every token. Anything else answers active: false",
		Tags:        []string{"oauth2"},
		RequestBody: serverHelpers.RequestBodyWithJSONAndForm[types.IntrospectTokenRequest](oauth2API, true, "OAuth2 token introspection request"),
	}, coreCtrl.HandleIntrospectToken)

	huma.Register(oauth2API, huma.Operation{
		OperationID: "oauth2RevokeToken",
		Method:      http.MethodPost,
		Path:        "/revoke",
		Summary:     "OAuth2 Token Revocation",
		Description: "Revokes the specified token",
		Tags:        []string{"oauth2"},
		RequestBody: serverHelpers.RequestBodyWithJSONAndForm[types.RevokeTokenRequest](oauth2API, true, "OAuth2 token revocation request"),
	}, coreCtrl.HandleRevokeToken)
}
