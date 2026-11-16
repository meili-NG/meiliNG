package oauth2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
	mctx "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/context"
)

// AuthController handles OAuth2 client authorization operations
type AuthController struct {
	controllers.Base
}

// NewAuthController creates a new OAuth2 auth controller
func NewAuthController(a *app.Meiling) *AuthController {
	return &AuthController{Base: controllers.NewBase(a)}
}

func (c *AuthController) HandleAuthEndpointCall(ctx context.Context, input *AuthEndpointCallInput) (*AuthEndpointCallOutput, error) {
	caller := mctx.GetPrincipal(ctx)
	if caller == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "caller not found")
	}

	result, err := api.GetOAuth2AuthConsent(api.OAuth2AuthRequest{
		Config:               c.Config(),
		TokenServices:        c.TokenServices(),
		Caller:               caller,
		ClientID:             input.AppID,
		UserID:               input.UserID,
		ResponseType:         input.ResponseType,
		Prompt:               input.Prompt,
		RedirectURI:          input.RedirectURI,
		Scope:                input.Scope,
		IncludeGrantedScopes: input.IncludeGrantedScopes,
		MaxAge:               input.MaxAge,
		ACRValues:            input.ACRValues,
	})
	if err != nil {
		return nil, err
	}

	return &AuthEndpointCallOutput{Body: result}, nil
}

func (c *AuthController) HandleAuthorizeClient(ctx context.Context, input *AuthorizeClientInput) (*AuthorizeClientOutput, error) {
	caller := mctx.GetPrincipal(ctx)
	if caller == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "caller not found")
	}

	result, err := api.AuthorizeOAuth2Client(api.OAuth2AuthRequest{
		Config:               c.Config(),
		TokenServices:        c.TokenServices(),
		Caller:               caller,
		ClientID:             input.AppID,
		UserID:               input.UserID,
		ResponseType:         input.ResponseType,
		Prompt:               input.Prompt,
		RedirectURI:          input.RedirectURI,
		Scope:                input.Scope,
		IncludeGrantedScopes: input.IncludeGrantedScopes,
		Approve:              input.Approve,
		CodeChallenge:        input.CodeChallenge,
		CodeChallengeMethod:  input.CodeChallengeMethod,
		AccessType:           input.AccessType,
		State:                input.State,
		Nonce:                input.Nonce,
		MaxAge:               input.MaxAge,
		ACRValues:            input.ACRValues,
	})
	if err != nil {
		return nil, err
	}

	return &AuthorizeClientOutput{Body: result}, nil
}

func (c *AuthController) HandleAuthorizeDeviceCode(ctx context.Context, input *AuthorizeDeviceCodeInput) (*types.BlankBody, error) {
	caller := mctx.GetPrincipal(ctx)
	if caller == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "caller not found")
	}

	if err := api.AuthorizeOAuth2DeviceCode(c.TokenServices(), caller, input.Body); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

// HandleConfirmEndSession carries out an RP-initiated logout the user
// confirmed. It needs the user's session; admin credentials have none.
func (c *AuthController) HandleConfirmEndSession(ctx context.Context, input *ConfirmEndSessionInput) (*ConfirmEndSessionOutput, error) {
	session, err := c.RequireUserSession(ctx)
	if err != nil {
		return nil, err
	}
	result, err := api.EndSession(c.TokenServices(), session, api.EndSessionRequest{
		IDTokenHint: input.Body.IDTokenHint, ClientID: input.Body.ClientID,
		PostLogoutRedirectURI: input.Body.PostLogoutRedirectURI, State: input.Body.State,
	}, input.Body.UserID)
	if err != nil {
		return nil, err
	}
	return &ConfirmEndSessionOutput{Body: result}, nil
}
