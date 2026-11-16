// Package meiling re-exports the Meiling authentication system from pkg/app.
package meiling

import (
	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/server/routes"
)

// Meiling is the main entry point for the Meiling authentication system
type Meiling = app.Meiling

func init() {
	// Register the router factory
	app.SetRouterFactory(func(fiberApp *fiber.App, m *app.Meiling, name string) app.Router {
		return routes.NewRouter(fiberApp, m, name)
	})
}

// New creates a new Meiling instance
func New(cfg config.MeilingConfig) (*Meiling, error) {
	return app.New(cfg)
}

// NewFromPath creates a new Meiling instance from a specific config path
func NewFromPath(path string) (*Meiling, error) {
	return app.NewFromPath(path)
}
