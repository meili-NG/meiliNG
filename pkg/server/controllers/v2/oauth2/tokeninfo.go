package oauth2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// TokenInfoController handles OAuth2 token info operations
type TokenInfoController struct {
	controllers.Base
}

// NewTokenInfoController creates a new OAuth2 token info controller
func NewTokenInfoController(a *app.Meiling) *TokenInfoController {
	return &TokenInfoController{Base: controllers.NewBase(a)}
}

func (c *TokenInfoController) HandleTokenInfoGet(ctx context.Context, input *TokenInfoGetInput) (*TokenInfoOutput, error) {
	result, err := api.GetOAuth2TokenInfo(c.TokenServices(), input.AccessToken, input.RefreshToken, input.IDToken)
	if err != nil {
		return nil, err
	}

	return &TokenInfoOutput{Body: result}, nil
}

func (c *TokenInfoController) HandleTokenInfoPost(ctx context.Context, input *TokenInfoPostInput) (*TokenInfoOutput, error) {
	accessToken := input.AccessToken
	if accessToken == "" && input.Body != nil {
		accessToken = input.Body.AccessToken
	}

	refreshToken := input.RefreshToken
	if refreshToken == "" && input.Body != nil {
		refreshToken = input.Body.RefreshToken
	}

	idToken := input.IDToken
	if idToken == "" && input.Body != nil {
		idToken = input.Body.IDToken
	}

	result, err := api.GetOAuth2TokenInfo(c.TokenServices(), accessToken, refreshToken, idToken)
	if err != nil {
		return nil, err
	}

	return &TokenInfoOutput{Body: result}, nil
}

func (c *TokenInfoController) HandleUserInfoGet(ctx context.Context, input *UserInfoGetInput) (*UserInfoOutput, error) {
	result, err := api.GetOAuth2UserInfo(c.TokenServices(), input.Authorization)
	if err != nil {
		return nil, err
	}

	return &UserInfoOutput{Body: result}, nil
}

func (c *TokenInfoController) HandleUserInfoPost(ctx context.Context, input *UserInfoPostInput) (*UserInfoOutput, error) {
	authorization := input.Authorization
	bodyAccessToken := ""
	if input.Body != nil {
		bodyAccessToken = input.Body.AccessToken
	}

	if authorization != "" && bodyAccessToken != "" {
		return nil, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "multiple access token transmission methods are not allowed")
	}
	if authorization == "" {
		authorization = bodyAccessToken
	}

	result, err := api.GetOAuth2UserInfo(c.TokenServices(), authorization)
	if err != nil {
		return nil, err
	}

	return &UserInfoOutput{Body: result}, nil
}
