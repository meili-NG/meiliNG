package v2

import (
	"sync"

	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2/oauth2"
)

// Registry holds instances of all V2 controllers.
// Each Registry is bound to a specific Meiling instance.
type Registry struct {
	app *app.Meiling
	mu  sync.RWMutex

	// Auth
	authController      *AuthController
	challengeController *ChallengeController

	// Session
	sessionController *SessionController

	// Admin
	adminController *AdminController

	// User
	userController *UserController

	// Permissions
	permissionsController *PermissionsController

	// Applications
	applicationsController *ApplicationsController

	// OAuth2 (registry from pkg/server/controllers/v2/oauth2)
	oauth2Registry *oauth2.Registry

	// Well-Known
	wellKnownController *WellKnownController

	// JWKS (global, not OAuth2-specific)
	jwksController *JWKSController

	// Instance description
	instanceController *InstanceController
}

// NewRegistry creates a new Registry bound to the given Meiling instance.
// Controllers created from this registry will have access to Meiling state.
func NewRegistry(a *app.Meiling) *Registry {
	return &Registry{app: a}
}

// App returns the Meiling instance this registry is bound to.
func (r *Registry) App() *app.Meiling {
	return r.app
}

// Auth Controllers

// GetAuthController returns the auth controller for this registry
func (r *Registry) GetAuthController() *AuthController {
	return utils.LazyGet(&r.mu, &r.authController, func() *AuthController {
		return NewAuthController(r.app)
	})
}

// GetChallengeController returns the challenge controller for this registry
func (r *Registry) GetChallengeController() *ChallengeController {
	return utils.LazyGet(&r.mu, &r.challengeController, func() *ChallengeController {
		return NewChallengeController(r.app)
	})
}

// Session Controllers

// GetSessionController returns the session controller for this registry
func (r *Registry) GetSessionController() *SessionController {
	return utils.LazyGet(&r.mu, &r.sessionController, func() *SessionController {
		return NewSessionController(r.app)
	})
}

// Admin Controllers

// GetAdminController returns the admin controller for this registry
func (r *Registry) GetAdminController() *AdminController {
	return utils.LazyGet(&r.mu, &r.adminController, func() *AdminController {
		return NewAdminController(r.app)
	})
}

// User Controllers

// GetUserController returns the user controller for this registry
func (r *Registry) GetUserController() *UserController {
	return utils.LazyGet(&r.mu, &r.userController, func() *UserController {
		return NewUserController(r.app)
	})
}

// Permission Controllers

// GetPermissionsController returns the permissions controller for this registry
func (r *Registry) GetPermissionsController() *PermissionsController {
	return utils.LazyGet(&r.mu, &r.permissionsController, func() *PermissionsController {
		return NewPermissionsController(r.app)
	})
}

// Application Controllers

// GetApplicationsController returns the applications controller for this registry
func (r *Registry) GetApplicationsController() *ApplicationsController {
	return utils.LazyGet(&r.mu, &r.applicationsController, func() *ApplicationsController {
		return NewApplicationsController(r.app)
	})
}

// OAuth2 Registry

// GetOAuth2 returns the OAuth2 controller registry
func (r *Registry) GetOAuth2() *oauth2.Registry {
	return utils.LazyGet(&r.mu, &r.oauth2Registry, func() *oauth2.Registry {
		return oauth2.NewRegistry(r.app)
	})
}

// Well-Known Controllers

// GetWellKnownController returns the well-known controller for this registry
func (r *Registry) GetWellKnownController() *WellKnownController {
	return utils.LazyGet(&r.mu, &r.wellKnownController, func() *WellKnownController {
		return NewWellKnownController(r.app)
	})
}

// JWKS Controllers

// GetJWKSController returns the JWKS controller for this registry
func (r *Registry) GetJWKSController() *JWKSController {
	return utils.LazyGet(&r.mu, &r.jwksController, func() *JWKSController {
		return NewJWKSController(r.app)
	})
}

// GetInstanceController returns the instance controller for this registry
func (r *Registry) GetInstanceController() *InstanceController {
	return utils.LazyGet(&r.mu, &r.instanceController, func() *InstanceController {
		return NewInstanceController(r.app)
	})
}
