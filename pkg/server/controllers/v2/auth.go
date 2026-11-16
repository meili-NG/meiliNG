package v2

import (
	"context"
	"errors"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/captcha"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
	mctx "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/context"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// AuthController handles authentication HTTP endpoints
type AuthController struct {
	controllers.Base
}

// NewAuthController creates a new auth controller
func NewAuthController(a *app.Meiling) *AuthController {
	return &AuthController{Base: controllers.NewBase(a)}
}

// Handler methods - these are the Huma handlers

func (c *AuthController) HandleIForgot(ctx context.Context, input *IForgotInput) (*IForgotOutput, error) {
	err := api.IForgot(&api.IForgotRequest{
		TokenServices:  c.TokenServices(),
		Username:       input.Body.Username,
		OwnershipToken: input.Body.OwnershipToken,
		Password:       input.Body.Password,
	})
	if err != nil {
		return nil, err
	}
	return &IForgotOutput{Body: types.IForgotResponse{}}, nil
}

func (c *AuthController) HandleSignIn(ctx context.Context, input *SignInInput) (*SignInOutput, error) {
	sess, err := c.resolveOptionalSession(ctx, input.Authorization)
	if err != nil {
		return nil, err
	}

	var signInLogData *api.SignInLogData
	if fiberCtx := mctx.GetFiberCtx(ctx); fiberCtx != nil {
		signInLogData = &api.SignInLogData{
			IP:        fiberCtx.IP(),
			UserAgent: fiberCtx.Get("User-Agent"),
		}
	}

	result, err := api.SignIn(&api.SignInRequest{
		Config:         c.Config(),
		TokenServices:  c.TokenServices(),
		Session:        sess,
		SignInLogData:  signInLogData,
		Username:       input.Body.Username,
		ID:             input.Body.ID,
		ChallengeToken: input.Body.ChallengeToken,
		UseWebAuthn:    input.Body.UseWebAuthn,
	})
	if err != nil {
		return nil, err
	}

	if result.RequiresChallenge {
		return &SignInOutput{Body: types.ChallengeRequest{
			Action:         types.ChallengeAction,
			ChallengeToken: result.ChallengeToken,
		}}, nil
	}

	return &SignInOutput{Body: types.BlankStruct{}}, nil
}

func (c *AuthController) HandleSignUpCheck(ctx context.Context, input *SignUpCheckInput) (*SignUpCheckOutput, error) {
	result, err := api.GetSignUpConfig(c.Config())
	if err != nil {
		return nil, err
	}
	return &SignUpCheckOutput{Body: types.SignUpConfigSerialized{
		AllowSignUp:               result.AllowSignUp,
		EmailRequired:             result.EmailRequired,
		PhoneRequired:             result.PhoneRequired,
		UsernameRequired:          result.UsernameRequired,
		EmailVerificationRequired: result.EmailVerificationRequired,
		PhoneVerificationRequired: result.PhoneVerificationRequired,
	}}, nil
}

func (c *AuthController) HandleOwnershipVerify(ctx context.Context, input *OwnershipVerifyInput) (*OwnershipVerifyOutput, error) {
	if err := validator.ValidatePayloadOrError(input.Body); err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
	}

	// Sending a code requires a passed challenge when a captcha provider is
	// enabled; answering one (OwnershipToken + Response) does not.
	if input.Body.OwnershipToken == "" || input.Body.Response == "" {
		var remoteIP string
		if fiberCtx := mctx.GetFiberCtx(ctx); fiberCtx != nil {
			remoteIP = fiberCtx.IP()
		}
		if err := captcha.Check(ctx, c.Config(), input.Body.CaptchaToken, remoteIP); err != nil {
			if errors.Is(err, captcha.ErrFailed) {
				return nil, meilingErrors.NewMeilingError(meilingErrors.ErrCaptchaFailed, "captcha challenge required")
			}
			return nil, meilingErrors.NewInternalServerError("captcha verification failed", err)
		}
	}

	token, err := api.OwnershipVerify(&api.OwnershipVerifyRequest{
		Config:         c.Config(),
		TokenServices:  c.TokenServices(),
		Email:          input.Body.Email,
		Phone:          input.Body.Phone,
		OwnershipToken: input.Body.OwnershipToken,
		Response:       input.Body.Response,
		Language:       input.AcceptLanguage,
	})
	if err != nil {
		return nil, err
	}
	return &OwnershipVerifyOutput{Body: types.SignUpTokenResponse{Token: token}}, nil
}

func (c *AuthController) HandleSignUp(ctx context.Context, input *SignUpInput) (*types.BlankBody, error) {
	if err := validator.ValidatePayloadOrError(input.Body); err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
	}

	err := api.SignUp(&api.SignUpRequest{
		Config:         c.Config(),
		TokenServices:  c.TokenServices(),
		Email:          input.Body.Email,
		Phone:          input.Body.Phone,
		OwnershipToken: input.Body.OwnershipToken,
		Username:       input.Body.Username,
		Password:       input.Body.Password,
		Name:           input.Body.Name,
	})
	if err != nil {
		return nil, err
	}
	return &types.BlankBody{}, nil
}

func (c *AuthController) HandleSignOut(ctx context.Context, input *SignOutInput) (*SignOutOutput, error) {
	sess, err := c.resolveRequiredSession(ctx, input.Authorization)
	if err != nil {
		return nil, err
	}

	result, err := api.SignOut(&api.SignOutRequest{
		TokenServices: c.TokenServices(),
		Session:       sess,
	})
	if err != nil {
		return nil, err
	}

	// Controller responsibility: session tracking (sign-out log)
	if len(result.UserIDs) > 0 {
		_ = api.MarkSignOut(sess, result.UserIDs...)
	}

	return &SignOutOutput{Body: SignOutResponse{FrontchannelLogoutURIs: result.FrontchannelLogoutURIs}}, nil
}

// resolveOptionalSession returns the caller's session, if any. Admin
// credentials have no session to sign users into or out of, so they are
// refused rather than treated as one.
func (c *AuthController) resolveOptionalSession(ctx context.Context, authorization string) (*tokens.SessionPayload, error) {
	principal, err := c.ResolveOptionalPrincipal(ctx, authorization)
	if err != nil || principal == nil {
		return nil, err
	}
	if principal.Session == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "admin credentials cannot sign users in or out")
	}
	return principal.Session, nil
}

func (c *AuthController) resolveRequiredSession(ctx context.Context, authorization string) (*tokens.SessionPayload, error) {
	session, err := c.resolveOptionalSession(ctx, authorization)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session not found")
	}
	return session, nil
}
