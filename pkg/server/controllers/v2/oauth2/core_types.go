package oauth2

import "github.com/meili-NG/meiliNG/v2/internal/types"

// AuthRedirectPostRequest represents the request body for a form-encoded OAuth2/OIDC authorization request.
type AuthRedirectPostRequest struct {
	ClientID             string `json:"client_id" form:"client_id" doc:"Client ID" required:"true"`
	RedirectURI          string `json:"redirect_uri" form:"redirect_uri" doc:"Redirect URI" required:"true"`
	ResponseType         string `json:"response_type" form:"response_type" doc:"Response Type" enum:"code,token" required:"true"`
	AccessType           string `json:"access_type" form:"access_type" doc:"Access Type" enum:"offline,online" required:"false"`
	Scope                string `json:"scope" form:"scope" doc:"Space separated scopes" required:"true"`
	State                string `json:"state" form:"state" doc:"State" required:"false"`
	Prompt               string `json:"prompt" form:"prompt" doc:"Space separated prompt values" required:"false"`
	IncludeGrantedScopes string `json:"include_granted_scopes" form:"include_granted_scopes" doc:"Include Granted Scopes; a boolean, anything else counts as false" required:"false"`
	LoginHint            string `json:"login_hint" form:"login_hint" doc:"Login Hint" required:"false"`
	CodeChallenge        string `json:"code_challenge" form:"code_challenge" doc:"Code Challenge" required:"false"`
	CodeChallengeMethod  string `json:"code_challenge_method" form:"code_challenge_method" doc:"Code Challenge Method" required:"false"`
	Display              string `json:"display" form:"display" doc:"Display" required:"false"`
	Nonce                string `json:"nonce" form:"nonce" doc:"Nonce" required:"false"`
	MaxAge               string `json:"max_age" form:"max_age" doc:"OIDC max_age" required:"false"`
	ACRValues            string `json:"acr_values" form:"acr_values" doc:"OIDC acr_values" required:"false"`
}

// AuthRedirectInput represents the input for OAuth2 auth redirect
type AuthRedirectInput struct {
	ClientID             string `query:"client_id" doc:"Client ID" required:"true"`
	RedirectURI          string `query:"redirect_uri" doc:"Redirect URI" required:"true"`
	ResponseType         string `query:"response_type" doc:"Response Type" enum:"code,token" required:"true"`
	AccessType           string `query:"access_type" doc:"Access Type" enum:"offline,online" required:"false"`
	Scope                string `query:"scope" doc:"Space separated scopes" required:"true"`
	State                string `query:"state" doc:"State" required:"false"`
	Prompt               string `query:"prompt" doc:"Space separated prompt values" required:"false"`
	IncludeGrantedScopes bool   `query:"include_granted_scopes" doc:"Include Granted Scopes" required:"false"`
	LoginHint            string `query:"login_hint" doc:"Login Hint" required:"false"`
	CodeChallenge        string `query:"code_challenge" doc:"Code Challenge" required:"false"`
	CodeChallengeMethod  string `query:"code_challenge_method" doc:"Code Challenge Method" required:"false"`
	Display              string `query:"display" doc:"Display" required:"false"`
	Nonce                string `query:"nonce" doc:"Nonce" required:"false"`
	MaxAge               string `query:"max_age" doc:"OIDC max_age" required:"false"`
	ACRValues            string `query:"acr_values" doc:"OIDC acr_values" required:"false"`
}

// AuthRedirectPostInput represents the POST input for OAuth2 auth redirect.
type AuthRedirectPostInput struct {
	Body AuthRedirectPostRequest
}

// AuthRedirectOutput represents the output for OAuth2 auth redirect
type AuthRedirectOutput struct {
	Location string `header:"Location" doc:"Redirect location"`
}

// TokenRequestInput represents the input for token exchange
type TokenRequestInput struct {
	Authorization string `header:"Authorization" doc:"Basic auth with client credentials" required:"false"`
	Body          types.TokenRequest
}

// TokenResponseOutput represents the output for token exchange
type TokenResponseOutput struct {
	Body types.TokenResponse
}

// DeviceAuthorizationInput represents the input for OAuth2 device authorization.
type DeviceAuthorizationInput struct {
	Authorization string `header:"Authorization" doc:"Basic auth with client credentials" required:"false"`
	Body          types.DeviceAuthorizationRequest
}

// DeviceAuthorizationOutput represents the output for OAuth2 device authorization.
type DeviceAuthorizationOutput struct {
	Body types.DeviceAuthorizationResponse
}

// IntrospectTokenInput is an RFC 7662 introspection request.
type IntrospectTokenInput struct {
	Authorization string `header:"Authorization" doc:"Basic auth with client credentials" required:"false"`
	Body          types.IntrospectTokenRequest
}

// IntrospectTokenOutput is an RFC 7662 introspection response.
type IntrospectTokenOutput struct {
	Body types.IntrospectionResponse
}

// RevokeTokenInput represents the input for token revocation
type RevokeTokenInput struct {
	Body types.RevokeTokenRequest
}

// EndSessionRequest is an OpenID Connect RP-initiated logout request.
type EndSessionRequest struct {
	IDTokenHint           string `json:"id_token_hint" form:"id_token_hint" doc:"An ID token this instance issued to the client; it may have expired" required:"false"`
	ClientID              string `json:"client_id" form:"client_id" doc:"Client ID" required:"false"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri" form:"post_logout_redirect_uri" doc:"Registered URI to return to" required:"false"`
	State                 string `json:"state" form:"state" doc:"State passed back on post_logout_redirect_uri" required:"false"`
}

// EndSessionInput is an RP-initiated logout request in the query.
type EndSessionInput struct {
	IDTokenHint           string `query:"id_token_hint" doc:"An ID token this instance issued to the client; it may have expired" required:"false"`
	ClientID              string `query:"client_id" doc:"Client ID" required:"false"`
	PostLogoutRedirectURI string `query:"post_logout_redirect_uri" doc:"Registered URI to return to" required:"false"`
	State                 string `query:"state" doc:"State passed back on post_logout_redirect_uri" required:"false"`
}

// EndSessionPostInput is an RP-initiated logout request in a form.
type EndSessionPostInput struct {
	Body EndSessionRequest
}
