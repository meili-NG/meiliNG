package routes

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"
	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	controllersV2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

// WellKnownRouter handles well-known routes
type WellKnownRouter struct {
	fiberApp *fiber.App
	app      *app.Meiling
	config   huma.Config
}

// NewWellKnownRouter creates a new WellKnownRouter instance
func NewWellKnownRouter(fiberApp *fiber.App, a *app.Meiling, name string) *WellKnownRouter {
	return &WellKnownRouter{
		fiberApp: fiberApp,
		app:      a,
		config:   serverHelpers.HumaConfigFor(a.Config()),
	}
}

// Register registers all well-known routes
func (r *WellKnownRouter) Register(wellKnown fiber.Router) {
	wellKnownAPI := humafiber.NewWithGroup(r.fiberApp, wellKnown, r.config)

	registry := controllersV2.NewRegistry(r.app)
	ctrl := registry.GetWellKnownController()

	// OpenID Configuration
	huma.Register(wellKnownAPI, huma.Operation{
		OperationID: "getOpenIDConfiguration",
		Method:      http.MethodGet,
		Path:        "/openid-configuration",
		Summary:     "OpenID Connect Discovery",
		Description: "Returns the OpenID Connect configuration",
		Tags:        []string{"well-known"},
	}, ctrl.HandleOpenIDConfiguration)
}
