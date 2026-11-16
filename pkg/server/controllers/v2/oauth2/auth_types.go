package oauth2

import (
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
)

// AuthEndpointCallInput represents the input for auth endpoint call
type AuthEndpointCallInput struct {
	Authorization        string `header:"Authorization" doc:"Session token" required:"true"`
	AppID                string `path:"app_id" doc:"Application ID" required:"true"`
	ResponseType         string `query:"response_type" doc:"Response Type" required:"true"`
	Scope                string `query:"scope" doc:"Scope" required:"true"`
	Prompt               string `query:"prompt" doc:"Space separated prompt values" required:"false"`
	RedirectURI          string `query:"redirect_uri" doc:"Redirect URI" required:"true"`
	IncludeGrantedScopes bool   `query:"include_granted_scopes" doc:"Include Granted Scopes" required:"false"`
	UserID               string `query:"user_id" doc:"User ID" required:"true"`
	MaxAge               string `query:"max_age" doc:"OIDC max_age: seconds since the user signed in after which they sign in again" required:"false"`
	ACRValues            string `query:"acr_values" doc:"OIDC acr_values: acceptable acr values (1fa, 2fa), space-delimited" required:"false"`
}

// AuthEndpointCallOutput represents the output for auth endpoint call
type AuthEndpointCallOutput struct {
	Body types.UserConsentRequest
}

// AuthorizeClientInput represents the input for authorize client
type AuthorizeClientInput struct {
	Authorization        string `header:"Authorization" doc:"Session token" required:"true"`
	AppID                string `path:"app_id" doc:"Application ID" required:"true"`
	RedirectURI          string `query:"redirect_uri" doc:"Redirect URI" required:"true"`
	ResponseType         string `query:"response_type" doc:"Response Type" enum:"code,token" required:"true"`
	AccessType           string `query:"access_type" doc:"Access Type" enum:"offline,online" required:"false"`
	Scope                string `query:"scope" doc:"Space separated scope" required:"true"`
	Prompt               string `query:"prompt" doc:"Space separated prompt values" required:"false"`
	IncludeGrantedScopes bool   `query:"include_granted_scopes" doc:"Include Granted Scopes" required:"false"`
	Approve              bool   `query:"approve" doc:"The user's explicit approval of the permissions the consent check lists. Without it the request is refused with consent_required while any are pending." required:"false"`
	CodeChallenge        string `query:"code_challenge" doc:"Code Challenge for validating response" required:"false"`
	CodeChallengeMethod  string `query:"code_challenge_method" doc:"Code Challenge Method" enum:"S256,plain" required:"false"`
	UserID               string `query:"user_id" doc:"User ID" required:"true"`
	State                string `query:"state" doc:"State" required:"false"`
	Nonce                string `query:"nonce" doc:"Nonce" required:"false"`
	MaxAge               string `query:"max_age" doc:"OIDC max_age: seconds since the user signed in after which they sign in again" required:"false"`
	ACRValues            string `query:"acr_values" doc:"OIDC acr_values: acceptable acr values (1fa, 2fa), space-delimited" required:"false"`
}

// AuthorizeClientOutput represents the output for authorize client
type AuthorizeClientOutput struct {
	Body types.AuthorizeResponse
}

// AuthorizeDeviceCodeInput represents the input for authorizing a device code.
type AuthorizeDeviceCodeInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"true"`
	Body          types.DeviceAuthorizeRequest
}

// ConfirmEndSessionRequest confirms an RP-initiated logout, with the request
// the frontend was given.
type ConfirmEndSessionRequest struct {
	IDTokenHint           string `json:"idTokenHint,omitempty" required:"false"`
	ClientID              string `json:"clientId,omitempty" required:"false"`
	PostLogoutRedirectURI string `json:"postLogoutRedirectUri,omitempty" required:"false"`
	State                 string `json:"state,omitempty" required:"false"`
	UserID                string `json:"userId,omitempty" doc:"The user to sign out when there is no ID token hint; every user of the session when empty" required:"false"`
}

// ConfirmEndSessionInput confirms an RP-initiated logout.
type ConfirmEndSessionInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"true"`
	Body          ConfirmEndSessionRequest
}

// ConfirmEndSessionOutput is where the browser goes next.
type ConfirmEndSessionOutput struct {
	Body api.EndSessionResult
}
