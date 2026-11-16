package app

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	jsoniter "github.com/json-iterator/go"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
)

// createFiberConfig builds the Fiber configuration
func (m *Meiling) createFiberConfig() fiber.Config {
	cfg := m.config

	fiberConfig := fiber.Config{
		AppName:     cfg.InstanceConfig.Name,
		JSONEncoder: jsoniter.ConfigFastest.Marshal,
		JSONDecoder: jsoniter.ConfigFastest.Unmarshal,
	}

	if len(cfg.ServerConfig.ProxyAddresses) > 0 {
		fiberConfig.EnableTrustedProxyCheck = true
		fiberConfig.TrustedProxies = cfg.ServerConfig.ProxyAddresses
		fiberConfig.ProxyHeader = cfg.ServerConfig.ProxyHeader
	}

	if cfg.ServerConfig.Prefork {
		fiberConfig.Prefork = true
	}

	fiberConfig.ErrorHandler = m.errorHandler

	return fiberConfig
}

// errorHandler handles Fiber errors
func (m *Meiling) errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	message := "Internal Server Error"

	var fiberErr *fiber.Error
	var meilingErr *meilingErrors.Error
	if errors.As(err, &fiberErr) {
		code = fiberErr.Code
		message = fiberErr.Message
	} else if errors.As(err, &meilingErr) {
		return c.Status(meilingErr.GetStatus()).JSON(meilingErr.ToJSON())
	}

	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Status(code).JSON(fiber.Map{
		"error":   true,
		"message": message,
	})
}

// GetServer returns the Fiber app instance, initializing if needed
func (m *Meiling) GetServer() (*fiber.App, error) {
	if err := m.initialize(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.fiberApp == nil {
		fiberConfig := m.createFiberConfig()
		fiberApp := fiber.New(fiberConfig)

		// Telemetry goes first so it sees the whole request.
		if m.reporter != nil {
			for _, h := range m.reporter.Middleware {
				fiberApp.Use(h)
			}
		}

		// Logger middleware
		fiberApp.Use(logger.New(logger.Config{
			Next: skipRequestLog,
		}))

		// Browser apps of any origin use the OAuth2/OIDC endpoints; the rest of
		// the API answers cross-origin requests only from server.frontendOrigins.
		fiberApp.Use(cors.New(cors.Config{
			Next:         func(c *fiber.Ctx) bool { return !isPublicOAuth2Path(c.Path()) },
			AllowOrigins: "*",
			AllowHeaders: "Authorization, Content-Type",
		}))
		fiberApp.Use(cors.New(cors.Config{
			Next:             func(c *fiber.Ctx) bool { return isPublicOAuth2Path(c.Path()) },
			AllowOriginsFunc: m.config.ServerConfig.AllowsOrigin,
			AllowHeaders:     "Authorization, Content-Type",
		}))

		// Extension middleware runs after core's and before every route.
		for _, h := range ext.Middleware(m) {
			fiberApp.Use(h)
		}

		// Register all routes using the factory
		var router Router
		if routerFactory != nil {
			router = routerFactory(fiberApp, m, m.config.InstanceConfig.Name)
			if err := router.Register(); err != nil {
				return nil, err
			}
		}

		// Only keep a fully registered app, so a failed attempt is retried
		// rather than serving a partial route table.
		m.fiberApp = fiberApp
		m.router = router
	}

	return m.fiberApp, nil
}

// GetRouter returns the router instance, initializing if needed
func (m *Meiling) GetRouter() (Router, error) {
	if _, err := m.GetServer(); err != nil {
		return nil, err
	}
	return m.router, nil
}

// StartServer starts the Meiling server
func (m *Meiling) StartServer() error {
	app, err := m.GetServer()
	if err != nil {
		return err
	}

	addr := m.getListenAddress()

	// Requests go through dispatch, so Reload can swap the app behind the
	// listening server.
	m.current.Store(&generation{handler: app.Handler(), owner: m})
	app.Server().Handler = m.dispatch

	// Check for unix socket
	if m.listener != nil {
		return app.Listener(m.listener)
	}

	return app.Listen(addr)
}

// getListenAddress returns the configured listen address
func (m *Meiling) getListenAddress() string {
	cfg := m.config

	addr := cfg.ServerConfig.Listen
	if addr == "" {
		addr = ":8080"
	}

	return addr
}

// SetListener sets a custom listener (useful for unix sockets)
func (m *Meiling) SetListener(listener net.Listener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listener = listener
}

// Shutdown gracefully shuts down the server
func (m *Meiling) Shutdown() error {
	m.mu.RLock()
	app, reporter := m.fiberApp, m.reporter
	m.mu.RUnlock()

	var errs []error
	if app != nil {
		if err := app.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := ext.RunShutdowners(context.Background()); err != nil {
		errs = append(errs, err)
	}
	if reporter != nil && reporter.Shutdown != nil {
		// Bounded, so an unreachable collector cannot hang shutdown.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := reporter.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// publicOAuth2Paths are the endpoints browser apps of any origin call: token
// exchange, token introspection and revocation, userinfo and key discovery.
var publicOAuth2Paths = []string{
	"/v2/oauth2/token",
	"/v2/oauth2/tokeninfo",
	"/v2/oauth2/userinfo",
	"/v2/oauth2/revoke",
	"/v2/oauth2/device",
	"/v2/jwks",
}

func isPublicOAuth2Path(path string) bool {
	if strings.HasPrefix(path, "/.well-known/") {
		return true
	}
	path = strings.TrimSuffix(path, "/")
	for _, p := range publicOAuth2Paths {
		if strings.EqualFold(path, p) {
			return true
		}
	}
	return false
}
