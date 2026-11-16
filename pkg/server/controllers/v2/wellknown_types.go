package v2

// OpenIDConfigurationInput represents the input for OpenID configuration (empty)
type OpenIDConfigurationInput struct {
	Host string `header:"Host" doc:"Host header for generating URLs" required:"false"`
}

// OpenIDConfigurationResponse represents the OpenID configuration response
type OpenIDConfigurationResponse struct {
	Issuer                             string   `json:"issuer"`
	AuthorizationEndpoint              string   `json:"authorization_endpoint"`
	UserinfoEndpoint                   string   `json:"userinfo_endpoint"`
	JwksURI                            string   `json:"jwks_uri"`
	ResponseTypesSupported             []string `json:"response_types_supported"`
	SubjectTypesSupported              []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported   []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpoint                      string   `json:"token_endpoint"`
	IntrospectionEndpoint              string   `json:"introspection_endpoint"`
	RevocationEndpoint                 string   `json:"revocation_endpoint"`
	EndSessionEndpoint                 string   `json:"end_session_endpoint"`
	BackchannelLogoutSupported         bool     `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported  bool     `json:"backchannel_logout_session_supported"`
	FrontchannelLogoutSupported        bool     `json:"frontchannel_logout_supported"`
	FrontchannelLogoutSessionSupported bool     `json:"frontchannel_logout_session_supported"`
	TokenEndpointAuthMethodsSupported  []string `json:"token_endpoint_auth_methods_supported"`
	DeviceAuthorizationEndpoint        string   `json:"device_authorization_endpoint"`
	GrantTypesSupported                []string `json:"grant_types_supported"`
	ScopesSupported                    []string `json:"scopes_supported"`
	ACRValuesSupported                 []string `json:"acr_values_supported"`
	ClaimsSupported                    []string `json:"claims_supported"`
	// MeilingClaimsNamespace prefixes Meiling's private claims (token_type,
	// grant_type, ...) in issued tokens, e.g. "<namespace>token_type".
	MeilingClaimsNamespace string `json:"meiling_claims_namespace"`
}

// OpenIDConfigurationOutput represents the output for OpenID configuration
type OpenIDConfigurationOutput struct {
	Body OpenIDConfigurationResponse
}
