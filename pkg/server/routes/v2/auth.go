package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	controllersV2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerAuthRoutes registers all authentication routes under /v2/auth
func (r *V2Router) registerAuthRoutes(v2API huma.API) {
	authAPI := huma.NewGroup(v2API, "/auth")
	authAPI.UseMiddleware(middleware.HumaValidateFrontendOrigins(r.app.Config()))

	authController := r.registry.GetAuthController()
	challengeController := r.registry.GetChallengeController()

	// Auth routes
	registerAuthOperations(authAPI, authController)

	// Challenge routes under /auth/challenge
	registerChallengeOperations(authAPI, challengeController)
}

// registerAuthOperations registers auth-specific operations
func registerAuthOperations(api huma.API, ctrl *controllersV2.AuthController) {
	huma.Register(api, huma.Operation{
		OperationID: "requestPasswordReset",
		Method:      http.MethodPost,
		Path:        "/iforgot",
		Summary:     "Request password reset",
		Description: "Request password reset using ownership verification",
		Tags:        []string{"auth"},
	}, ctrl.HandleIForgot)

	huma.Register(api, huma.Operation{
		OperationID: "signIn",
		Method:      http.MethodPost,
		Path:        "/signin",
		Summary:     "Sign in",
		Description: "Sign in with username/id or continue challenge flow",
		Tags:        []string{"auth"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleSignIn)

	huma.Register(api, huma.Operation{
		OperationID: "getSignUpConfig",
		Method:      http.MethodGet,
		Path:        "/signup",
		Summary:     "Check current configuration for signing up",
		Description: "Get the current signup configuration",
		Tags:        []string{"auth"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleSignUpCheck)

	huma.Register(api, huma.Operation{
		OperationID: "verifyOwnership",
		Method:      http.MethodPost,
		Path:        "/verify",
		Summary:     "Verify the specified resource's ownership",
		Description: "Verify ownership of email or phone",
		Tags:        []string{"auth"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleOwnershipVerify)

	huma.Register(api, huma.Operation{
		OperationID: "signUp",
		Method:      http.MethodPost,
		Path:        "/signup",
		Summary:     "Sign up",
		Description: "Create a new user account",
		Tags:        []string{"auth"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleSignUp)

	huma.Register(api, huma.Operation{
		OperationID: "signOutAll",
		Method:      http.MethodPost,
		Path:        "/signout",
		Summary:     "Sign out all users",
		Description: "Sign out all users in the session",
		Tags:        []string{"auth"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleSignOut)
}

// registerChallengeOperations registers challenge-specific operations
func registerChallengeOperations(api huma.API, ctrl *controllersV2.ChallengeController) {
	huma.Register(api, huma.Operation{
		OperationID: "getChallengeMethod",
		Method:      http.MethodGet,
		Path:        "/challenge",
		Summary:     "Get challenge Method",
		Description: "Get available challenge methods for the given challenge token",
		Tags:        []string{"challenge"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetChallenge)

	huma.Register(api, huma.Operation{
		OperationID: "issueChallenge",
		Method:      http.MethodPost,
		Path:        "/challenge/issue",
		Summary:     "Request challenge",
		Description: "Issue a challenge for the specified authentication type",
		Tags:        []string{"challenge"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleIssueChallenge)

	huma.Register(api, huma.Operation{
		OperationID: "validateChallenge",
		Method:      http.MethodPost,
		Path:        "/challenge/validate",
		Summary:     "Validate Challenge",
		Description: "Validate Challenge issued from issueChallenge, if not issued, it will automatically fall back if authenticator doesn't need challenge.",
		Tags:        []string{"challenge"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleValidateChallenge)
}
