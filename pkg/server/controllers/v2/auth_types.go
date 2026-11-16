package v2

import "github.com/meili-NG/meiliNG/v2/internal/types"

// Huma Input/Output types

type IForgotInput struct {
	Body types.IForgotRequest
}

type IForgotOutput struct {
	Body types.IForgotResponse
}

type SignInInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"false"`
	Body          types.SignInRequest
}

type SignInOutput struct {
	Body any
}

type SignUpCheckInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"false"`
}

type SignUpCheckOutput struct {
	Body types.SignUpConfigSerialized
}

type OwnershipVerifyInput struct {
	Authorization  string `header:"Authorization" doc:"Session token" required:"false"`
	AcceptLanguage string `header:"Accept-Language" doc:"The Language for sending verification code" required:"false"`
	Body           types.SignUpTokenRequest
}

type OwnershipVerifyOutput struct {
	Body types.SignUpTokenResponse
}

type SignUpInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"false"`
	Body          types.SignUpRequest
}

type SignOutInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"true"`
}

// SignOutResponse lists the applications' front-channel logout URIs, for the
// browser to load so they end their own sessions too.
type SignOutResponse struct {
	FrontchannelLogoutURIs []string `json:"frontchannelLogoutUris"`
}

// SignOutOutput is the sign-out response.
type SignOutOutput struct {
	Body SignOutResponse
}
