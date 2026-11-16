package oauth2

import (
	"context"
	"strconv"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// CoreController handles core OAuth2 operations (auth redirect, token exchange, revoke)
type CoreController struct {
	controllers.Base
}

// NewCoreController creates a new OAuth2 core controller
func NewCoreController(a *app.Meiling) *CoreController {
	return &CoreController{Base: controllers.NewBase(a)}
}

func (c *CoreController) buildAuthRedirectOutput(input api.OAuth2AuthRedirectRequest) (*AuthRedirectOutput, error) {
	location, err := api.BuildOAuth2AuthRedirectURL(c.Config(), api.OAuth2AuthRedirectRequest{
		ClientID:             input.ClientID,
		RedirectURI:          input.RedirectURI,
		ResponseType:         input.ResponseType,
		Scope:                input.Scope,
		AccessType:           input.AccessType,
		State:                input.State,
		Prompt:               input.Prompt,
		IncludeGrantedScopes: input.IncludeGrantedScopes,
		LoginHint:            input.LoginHint,
		CodeChallenge:        input.CodeChallenge,
		CodeChallengeMethod:  input.CodeChallengeMethod,
		Display:              input.Display,
		Nonce:                input.Nonce,
		MaxAge:               input.MaxAge,
		ACRValues:            input.ACRValues,
	})
	if err != nil {
		return nil, err
	}

	return &AuthRedirectOutput{Location: location}, nil
}

func (c *CoreController) HandleAuthRedirect(ctx context.Context, input *AuthRedirectInput) (*AuthRedirectOutput, error) {
	return c.buildAuthRedirectOutput(api.OAuth2AuthRedirectRequest{
		ClientID:             input.ClientID,
		RedirectURI:          input.RedirectURI,
		ResponseType:         input.ResponseType,
		Scope:                input.Scope,
		AccessType:           input.AccessType,
		State:                input.State,
		Prompt:               input.Prompt,
		IncludeGrantedScopes: input.IncludeGrantedScopes,
		LoginHint:            input.LoginHint,
		CodeChallenge:        input.CodeChallenge,
		CodeChallengeMethod:  input.CodeChallengeMethod,
		Display:              input.Display,
		Nonce:                input.Nonce,
		MaxAge:               input.MaxAge,
		ACRValues:            input.ACRValues,
	})
}

func (c *CoreController) HandleAuthRedirectPost(ctx context.Context, input *AuthRedirectPostInput) (*AuthRedirectOutput, error) {
	// Lenient like the query parameter of the GET form: unparsable or empty is false.
	includeGrantedScopes, _ := strconv.ParseBool(input.Body.IncludeGrantedScopes)
	return c.buildAuthRedirectOutput(api.OAuth2AuthRedirectRequest{
		ClientID:             input.Body.ClientID,
		RedirectURI:          input.Body.RedirectURI,
		ResponseType:         input.Body.ResponseType,
		Scope:                input.Body.Scope,
		AccessType:           input.Body.AccessType,
		State:                input.Body.State,
		Prompt:               input.Body.Prompt,
		IncludeGrantedScopes: includeGrantedScopes,
		LoginHint:            input.Body.LoginHint,
		CodeChallenge:        input.Body.CodeChallenge,
		CodeChallengeMethod:  input.Body.CodeChallengeMethod,
		Display:              input.Body.Display,
		Nonce:                input.Body.Nonce,
		MaxAge:               input.Body.MaxAge,
		ACRValues:            input.Body.ACRValues,
	})
}

func (c *CoreController) HandleTokenExchange(ctx context.Context, input *TokenRequestInput) (*TokenResponseOutput, error) {
	result, err := api.ExchangeOAuth2Token(c.TokenServices(), input.Body, input.Authorization)
	if err != nil {
		return nil, err
	}

	return &TokenResponseOutput{Body: result}, nil
}

func (c *CoreController) HandleDeviceAuthorization(ctx context.Context, input *DeviceAuthorizationInput) (*DeviceAuthorizationOutput, error) {
	result, err := api.StartOAuth2DeviceAuthorization(c.Config(), c.TokenServices(), input.Body, input.Authorization)
	if err != nil {
		return nil, err
	}

	return &DeviceAuthorizationOutput{Body: result}, nil
}

func (c *CoreController) HandleRevokeToken(ctx context.Context, input *RevokeTokenInput) (*types.BlankBody, error) {
	if err := api.RevokeOAuth2Token(c.TokenServices(), input.Body.Token); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

// HandleIntrospectToken answers an RFC 7662 introspection request.
func (c *CoreController) HandleIntrospectToken(ctx context.Context, input *IntrospectTokenInput) (*IntrospectTokenOutput, error) {
	result, err := api.IntrospectOAuth2Token(c.TokenServices(), input.Body, input.Authorization)
	if err != nil {
		return nil, err
	}
	return &IntrospectTokenOutput{Body: result}, nil
}

// HandleEndSession checks an RP-initiated logout request and sends the browser
// to the frontend, which asks the user to confirm it.
func (c *CoreController) HandleEndSession(ctx context.Context, input *EndSessionInput) (*AuthRedirectOutput, error) {
	return c.endSessionRedirect(api.EndSessionRequest{
		IDTokenHint: input.IDTokenHint, ClientID: input.ClientID,
		PostLogoutRedirectURI: input.PostLogoutRedirectURI, State: input.State,
	})
}

// HandleEndSessionPost is HandleEndSession for a form-encoded request.
func (c *CoreController) HandleEndSessionPost(ctx context.Context, input *EndSessionPostInput) (*AuthRedirectOutput, error) {
	return c.endSessionRedirect(api.EndSessionRequest{
		IDTokenHint: input.Body.IDTokenHint, ClientID: input.Body.ClientID,
		PostLogoutRedirectURI: input.Body.PostLogoutRedirectURI, State: input.Body.State,
	})
}

func (c *CoreController) endSessionRedirect(req api.EndSessionRequest) (*AuthRedirectOutput, error) {
	location, err := api.BuildEndSessionRedirectURL(c.Config(), c.TokenServices(), req)
	if err != nil {
		return nil, err
	}
	return &AuthRedirectOutput{Location: location}, nil
}
