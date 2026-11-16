package routes

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
	middleware "github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
	v2 "github.com/meili-NG/meiliNG/v2/pkg/server/routes/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/server/webui"
)

// Router handles all API routes
type Router struct {
	fiberApp *fiber.App
	app      *app.Meiling
	name     string
}

// NewRouter creates a new Router instance
func NewRouter(fiberApp *fiber.App, a *app.Meiling, name string) *Router {
	return &Router{
		fiberApp: fiberApp,
		app:      a,
		name:     name,
	}
}

// Register registers all routes
func (r *Router) Register() error {
	// Register health check endpoint
	r.registerHealthRoute()

	// Register v2 routes
	v2Router := v2.NewV2Router(r.fiberApp, r.app, r.name)
	v2Router.Register()

	// Register well-known routes
	r.registerWellKnownRoutes()

	// Register swagger-ui redirect to Huma docs
	r.registerSwaggerRedirect()

	// Register root endpoint
	r.registerRootRoute()

	// Published signing keys: /{username}.keys, /{username}.gpg, /pks/lookup
	r.registerPublicKeyRoutes()

	// Extension routes come after every core route so they cannot shadow
	// one, and before the web UI so a UI mounted at "/" cannot hide them.
	if err := ext.RegisterRoutes(r.fiberApp, r.app); err != nil {
		return err
	}

	// Register the optional built-in web interface. This is last so it never
	// shadows an API route, and is a no-op unless webui.enable is set.
	r.registerWebUI()
	return nil
}

// registerWebUI mounts the built-in web interface when it is enabled.
func (r *Router) registerWebUI() {
	// Route registration runs while the app holds its instance lock, so use the
	// lock-free accessor here; the locking TokenServices() would self-deadlock.
	if err := webui.Register(r.fiberApp, r.app.Config(), r.app.TokenServicesLocked()); err != nil {
		log.Printf("webui: disabled, failed to mount: %v", err)
	}
}

// registerHealthRoute registers the health check endpoint
func (r *Router) registerHealthRoute() {
	r.fiberApp.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "OK",
			"name":   r.app.Config().InstanceConfig.Name,
		})
	})
}

// registerSwaggerRedirect redirects /swagger-ui to Huma's documentation endpoint
func (r *Router) registerSwaggerRedirect() {

	r.fiberApp.Get("/swagger-ui", func(c *fiber.Ctx) error {
		return c.Redirect("/docs", fiber.StatusFound)
	})
	r.fiberApp.Get("/swagger-ui/doc.json", func(c *fiber.Ctx) error {
		return c.Redirect("/openapi.json", fiber.StatusFound)
	})
}

// registerRootRoute registers the root "/" endpoint
func (r *Router) registerRootRoute() {
	cfg := r.app.Config()

	// When the web interface is mounted at the root it owns "/", and Fiber
	// resolves routes in registration order, so claiming "/" here would make
	// the UI unreachable. The same information stays available at /health.
	if webui.OwnsRoot(cfg) {
		return
	}

	r.fiberApp.Get("/", middleware.TryCheckSession(r.app), func(c *fiber.Ctx) error {
		about := fiber.Map{
			"name":        cfg.InstanceConfig.Name,
			"description": cfg.ServiceDescription(),
		}

		// Show the version only to admins.
		if middleware.IsAdmin(c) {
			about["version"] = app.Version
		}

		return c.JSON(fiber.Map{
			"hello": "world",
			"about": about,
		})
	})
}

// registerWellKnownRoutes registers well-known endpoints
func (r *Router) registerWellKnownRoutes() {
	wellKnown := r.fiberApp.Group("/.well-known")
	wkRouter := NewWellKnownRouter(r.fiberApp, r.app, r.name)
	wkRouter.Register(wellKnown)
}
