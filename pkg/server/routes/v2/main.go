package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"
	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	controllersV2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

// V2Router handles all v2 API routes
type V2Router struct {
	fiberApp *fiber.App
	app      *app.Meiling
	registry *controllersV2.Registry
	config   huma.Config
}

// NewV2Router creates a new V2Router instance
func NewV2Router(fiberApp *fiber.App, a *app.Meiling, name string) *V2Router {
	return &V2Router{
		fiberApp: fiberApp,
		app:      a,
		registry: controllersV2.NewRegistry(a),
		config:   serverHelpers.HumaConfigFor(a.Config()),
	}
}

// Register registers all v2 routes using nested Huma groups.
func (r *V2Router) Register() {
	api := humafiber.New(r.fiberApp, r.config)
	v2API := huma.NewGroup(api, "/v2")

	// Register route groups
	r.registerAuthRoutes(v2API)
	r.registerUserRoutes(v2API)
	r.registerSessionRoutes(v2API)
	r.registerAdminRoutes(v2API)
	r.registerPermissionRoutes(v2API)
	r.registerApplicationRoutes(v2API)
	r.registerApplicationAliases()
	r.registerOAuth2Routes(v2API)
	r.registerJWKSRoute(v2API)
	r.registerInstanceRoute(v2API)
}

// registerInstanceRoute registers the public instance description, which user
// interfaces read to present the instance.
func (r *V2Router) registerInstanceRoute(v2API huma.API) {
	ctrl := r.registry.GetInstanceController()

	huma.Register(v2API, huma.Operation{
		OperationID: "getInstance",
		Method:      http.MethodGet,
		Path:        "/instance",
		Summary:     "Describe this instance",
		Description: "Returns the public identity of this instance (name, description, logo, help link) for user interfaces to present it",
		Tags:        []string{"instance"},
	}, ctrl.HandleGetInstance)

	if cfg := r.app.Config(); cfg.AuthConfig.EnableKeyOwnerLookup && !cfg.AuthConfig.DisablePublicKeys {
		huma.Register(v2API, huma.Operation{
			OperationID: "getKeyOwner",
			Method:      http.MethodGet,
			Path:        "/keys",
			Summary:     "Find the owner of a public signing key",
			Description: "Returns the username owning the public SSH or OpenPGP key with the given fingerprint. Private keys are not found. Enabled by auth.enableKeyOwnerLookup",
			Tags:        []string{"instance"},
		}, ctrl.HandleGetKeyOwner)
	}
}

// registerJWKSRoute registers the JWKS endpoint
func (r *V2Router) registerJWKSRoute(v2API huma.API) {
	jwksCtrl := r.registry.GetJWKSController()

	huma.Register(v2API, huma.Operation{
		OperationID: "getJWKS",
		Method:      http.MethodGet,
		Path:        "/jwks",
		Summary:     "Get JSON Web Key Set",
		Description: "Returns the JSON Web Key Set for verifying tokens",
		Tags:        []string{"jwks"},
	}, jwksCtrl.HandleJWKS)
}
