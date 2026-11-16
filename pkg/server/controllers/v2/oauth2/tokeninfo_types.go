package oauth2

import (
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// TokenInfoGetInput represents the GET input for token info.
type TokenInfoGetInput struct {
	AccessToken  string `query:"access_token" doc:"Access Token" required:"false"`
	RefreshToken string `query:"refresh_token" doc:"Refresh Token" required:"false"`
	IDToken      string `query:"id_token" doc:"ID Token" required:"false"`
}

// TokenInfoPostInput represents the POST input for token info.
type TokenInfoPostInput struct {
	AccessToken  string `query:"access_token" doc:"Access Token" required:"false"`
	RefreshToken string `query:"refresh_token" doc:"Refresh Token" required:"false"`
	IDToken      string `query:"id_token" doc:"ID Token" required:"false"`
	Body         *TokenInfoPostRequest
}

// TokenInfoPostRequest represents the POST request body for token info.
type TokenInfoPostRequest struct {
	AccessToken  string `json:"access_token" required:"false"`
	RefreshToken string `json:"refresh_token" required:"false"`
	IDToken      string `json:"id_token" required:"false"`
}

// TokenInfoOutput represents the output for token info
type TokenInfoOutput struct {
	Body types.TokenResponse
}

// UserInfoGetInput represents the GET input for user info.
type UserInfoGetInput struct {
	Authorization string `header:"Authorization" doc:"Access token" required:"true"`
}

// UserInfoPostInput represents the POST input for user info.
type UserInfoPostInput struct {
	Authorization string `header:"Authorization" doc:"Access token" required:"false"`
	Body          *UserInfoPostRequest
}

// UserInfoPostRequest represents the POST request body for user info.
type UserInfoPostRequest struct {
	AccessToken string `json:"access_token" required:"false"`
}

// UserInfoOutput represents the output for user info
type UserInfoOutput struct {
	Body tokens.IDTokenContent
}
