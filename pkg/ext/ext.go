// Package ext is the extension surface of Meiling.
//
// Meiling core ships working defaults for everything and exposes these kinds of
// extension points that a distribution (a separate Go module with its own
// main package) uses to customise a build without patching core:
//
//   - Registries, for things where several implementations coexist and config
//     selects one by name: notification providers (notify.Register), database
//     types (config.RegisterDialect) and config sections
//     (config.RegisterSection).
//   - Config defaults (config.SetDefault), which replace the built-in default
//     of any config key while files and environment variables still win.
//   - Slots, for things that have exactly one active implementation with a
//     built-in default: message templates (pkg/notify/templates), the
//     embedded web UI build (webui.Assets), the GeoIP lookup (geoip.Provider),
//     the bot challenge (captcha.Provider), the fallback avatar
//     (avatar.Provider) and error and trace reporting
//     (telemetry.Provider). See Slot.
//   - Presets, for names a distribution may want to choose itself: the env
//     prefix and config directory (config.SetEnvPrefix, config.SetConfigDir),
//     session Authorization schemes (tokens.SessionSchemes), the OpenAPI
//     security scheme name (helpers.SessionSecurityScheme), the shared admin
//     token key (webui.MagicAdminTokenKey) and the CLI root command
//     (cli.Root).
//
// Components that need to take part in the server lifecycle implement
// Extension plus any of the optional hook interfaces below, and register from
// init() with Register.
//
// A distribution is wired entirely by imports in its main package:
//
//	package main
//
//	import (
//		"github.com/meili-NG/meiliNG/v2/cmd/meiling/cli"
//
//		_ "example.com/my-distribution/notify/myprovider"
//		_ "example.com/my-distribution/templates"
//	)
//
//	func main() { cli.Execute() }
//
// Everything an extension can name lives under pkg/; internal/ types never
// appear in this API, since other modules cannot import them.
package ext

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/spf13/cobra"
)

// Extension is a named component registered into a Meiling build. On its own
// it does nothing; implement one or more hook interfaces to take part in the
// lifecycle.
type Extension interface {
	// Name identifies the extension in logs and must be unique in a build.
	Name() string
}

// Host is the view of the running Meiling instance handed to hooks. Its
// dynamic type is *app.Meiling, which hooks may type-assert to when they need
// more, e.g. to build core's session middleware for their routes. Hooks run
// while the instance lock is held, so during the hook itself they must only
// call methods documented as lock-free (Config, TokenServicesLocked); the
// handlers they install are not restricted.
type Host interface {
	Config() *config.MeilingConfig
}

// Initializer is called while an instance initializes, after core
// dependencies (database, token services, notification providers) are ready:
// once at startup, and again with the new host after each configuration
// reload. Returning an error aborts startup, or the reload.
type Initializer interface {
	Init(ctx context.Context, host Host) error
}

// MiddlewareProvider adds app-wide HTTP middleware. It runs after core's
// telemetry, request-log and CORS middleware and before every route.
type MiddlewareProvider interface {
	Middleware(host Host) []fiber.Handler
}

// RouteRegistrar mounts HTTP routes. They are registered after core's API
// routes and before the web UI, and Fiber matches in registration order, so
// an extension can neither shadow a core endpoint nor be hidden by a UI
// mounted at "/".
type RouteRegistrar interface {
	RegisterRoutes(app *fiber.App, host Host) error
}

// Shutdowner releases resources on graceful shutdown, after the HTTP server
// has stopped accepting requests.
type Shutdowner interface {
	Shutdown(ctx context.Context) error
}

// CommandProvider adds subcommands to the meiling CLI. A command whose name
// or alias collides with an existing one is a startup error.
type CommandProvider interface {
	Commands() []*cobra.Command
}

var (
	registryMu sync.RWMutex
	registry   []Extension
	names      = map[string]bool{}
)

// Register adds an extension to the build. It panics on a nil extension, an
// empty name, or a duplicate name, as these are wiring bugs.
func Register(e Extension) {
	if e == nil {
		panic("ext: Register called with nil extension")
	}
	name := e.Name()
	if name == "" {
		panic("ext: Register called with an extension that has an empty name")
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	if names[name] {
		panic(fmt.Sprintf("ext: extension %q registered twice", name))
	}
	names[name] = true
	registry = append(registry, e)
}

// Extensions returns the registered extensions in registration order.
func Extensions() []Extension {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return append([]Extension(nil), registry...)
}

// RunInitializers calls Init on every registered Initializer, in registration
// order, stopping at the first error.
func RunInitializers(ctx context.Context, host Host) error {
	for _, e := range Extensions() {
		if i, ok := e.(Initializer); ok {
			if err := i.Init(ctx, host); err != nil {
				return fmt.Errorf("ext: initializing %q: %w", e.Name(), err)
			}
		}
	}
	return nil
}

// Middleware returns the middleware of every MiddlewareProvider, in
// registration order.
func Middleware(host Host) []fiber.Handler {
	var out []fiber.Handler
	for _, e := range Extensions() {
		if p, ok := e.(MiddlewareProvider); ok {
			out = append(out, p.Middleware(host)...)
		}
	}
	return out
}

// RegisterRoutes calls every RouteRegistrar, in registration order, stopping
// at the first error.
func RegisterRoutes(app *fiber.App, host Host) error {
	for _, e := range Extensions() {
		if r, ok := e.(RouteRegistrar); ok {
			if err := r.RegisterRoutes(app, host); err != nil {
				return fmt.Errorf("ext: registering routes of %q: %w", e.Name(), err)
			}
		}
	}
	return nil
}

// RunShutdowners calls every Shutdowner in reverse registration order, so an
// extension shuts down before the ones registered ahead of it. Every
// Shutdowner runs even if an earlier one fails; the errors are joined.
func RunShutdowners(ctx context.Context) error {
	exts := Extensions()
	var errs []error
	for i := len(exts) - 1; i >= 0; i-- {
		if s, ok := exts[i].(Shutdowner); ok {
			if err := s.Shutdown(ctx); err != nil {
				errs = append(errs, fmt.Errorf("ext: shutting down %q: %w", exts[i].Name(), err))
			}
		}
	}
	return errors.Join(errs...)
}
