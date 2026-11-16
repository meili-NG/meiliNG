package oauth2

import (
	"sync"

	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
)

// Registry holds instances of OAuth2 controllers.
// Each Registry is bound to a specific Meiling instance.
type Registry struct {
	app *app.Meiling
	mu  sync.RWMutex

	coreController         *CoreController
	tokenInfoController    *TokenInfoController
	secretsController      *SecretsController
	redirectURIsController *RedirectURIsController
	audiencesController    *AudiencesController
	authController         *AuthController
}

// NewRegistry creates a new Registry bound to the given Meiling instance.
func NewRegistry(a *app.Meiling) *Registry {
	return &Registry{app: a}
}

// App returns the Meiling instance this registry is bound to.
func (r *Registry) App() *app.Meiling {
	return r.app
}

// GetCoreController returns the OAuth2 core controller
func (r *Registry) GetCoreController() *CoreController {
	return utils.LazyGet(&r.mu, &r.coreController, func() *CoreController {
		return NewCoreController(r.app)
	})
}

// GetTokenInfoController returns the OAuth2 token info controller
func (r *Registry) GetTokenInfoController() *TokenInfoController {
	return utils.LazyGet(&r.mu, &r.tokenInfoController, func() *TokenInfoController {
		return NewTokenInfoController(r.app)
	})
}

// GetSecretsController returns the OAuth2 secrets controller
func (r *Registry) GetSecretsController() *SecretsController {
	return utils.LazyGet(&r.mu, &r.secretsController, func() *SecretsController {
		return NewSecretsController(r.app)
	})
}

// GetRedirectURIsController returns the OAuth2 redirect URIs controller
func (r *Registry) GetRedirectURIsController() *RedirectURIsController {
	return utils.LazyGet(&r.mu, &r.redirectURIsController, func() *RedirectURIsController {
		return NewRedirectURIsController(r.app)
	})
}

// GetAudiencesController returns the OAuth2 audiences controller
func (r *Registry) GetAudiencesController() *AudiencesController {
	return utils.LazyGet(&r.mu, &r.audiencesController, func() *AudiencesController {
		return NewAudiencesController(r.app)
	})
}

// GetAuthController returns the OAuth2 auth controller
func (r *Registry) GetAuthController() *AuthController {
	return utils.LazyGet(&r.mu, &r.authController, func() *AuthController {
		return NewAuthController(r.app)
	})
}
