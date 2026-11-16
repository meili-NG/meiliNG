package v2

import (
	"context"
	"github.com/meili-NG/meiliNG/v2/pkg/auth"

	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// WellKnownController handles well-known endpoint operations
type WellKnownController struct {
	controllers.Base
}

// NewWellKnownController creates a new well-known controller
func NewWellKnownController(a *app.Meiling) *WellKnownController {
	return &WellKnownController{Base: controllers.NewBase(a)}
}

// HandleOpenIDConfiguration returns the OpenID Connect configuration
func (c *WellKnownController) HandleOpenIDConfiguration(ctx context.Context, input *OpenIDConfigurationInput) (*OpenIDConfigurationOutput, error) {
	cfg := c.Config()

	issuer := cfg.TokenConfig.JWT.Issuer

	hostname := cfg.ServerConfig.PublicURL
	if hostname == "" && input.Host != "" {
		// Generate from Host header
		hostname = "https://" + input.Host
	}

	deviceAuthorizationEndpoint := c.generateAddress(hostname, "/v2/oauth2/device")
	if cfg.OAuth2Config.DeviceAuthorizationEndpoint != "" {
		deviceAuthorizationEndpoint = cfg.OAuth2Config.DeviceAuthorizationEndpoint
	}

	permissions, err := api.ListPublicPermissions()
	if err != nil {
		return nil, err
	}

	scopes := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		scopes = append(scopes, permission.Scope)
	}

	return &OpenIDConfigurationOutput{
		Body: OpenIDConfigurationResponse{
			Issuer:                issuer,
			AuthorizationEndpoint: c.generateAddress(hostname, "/v2/oauth2/auth"),
			UserinfoEndpoint:      c.generateAddress(hostname, "/v2/oauth2/userinfo"),
			JwksURI:               c.generateAddress(hostname, "/v2/jwks"),
			ResponseTypesSupported: []string{
				"code",
				"token",
			},
			SubjectTypesSupported: []string{
				"public",
			},
			IDTokenSigningAlgValuesSupported:   []string{cfg.TokenConfig.JWT.Algorithm},
			TokenEndpoint:                      c.generateAddress(hostname, "/v2/oauth2/token"),
			IntrospectionEndpoint:              c.generateAddress(hostname, "/v2/oauth2/introspect"),
			RevocationEndpoint:                 c.generateAddress(hostname, "/v2/oauth2/revoke"),
			EndSessionEndpoint:                 c.generateAddress(hostname, "/v2/oauth2/logout"),
			BackchannelLogoutSupported:         true,
			BackchannelLogoutSessionSupported:  true,
			FrontchannelLogoutSupported:        true,
			FrontchannelLogoutSessionSupported: true,
			TokenEndpointAuthMethodsSupported: []string{
				"none",
				"client_secret_basic",
				"client_secret_post",
			},
			DeviceAuthorizationEndpoint: deviceAuthorizationEndpoint,
			GrantTypesSupported: []string{
				"authorization_code",
				"client_credentials",
				"refresh_token",
				"urn:ietf:params:oauth:grant-type:device_code",
			},
			ScopesSupported:    scopes,
			ACRValuesSupported: []string{auth.ACRSingleFactor, auth.ACRMultiFactor},
			ClaimsSupported: []string{
				"sub", "iss", "aud", "exp", "iat", "nonce", "sid", "auth_time", "amr", "acr",
				"name", "given_name", "family_name", "preferred_username", "picture", "profile",
				"locale", "zoneinfo", "gender", "email", "email_verified", "phone_number", "phone_number_verified",
			},
			MeilingClaimsNamespace: c.TokenServices().JWT().ClaimsNamespace(),
		},
	}, nil
}

func (c *WellKnownController) generateAddress(hostname string, path string) string {
	return hostname + path
}
