package test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
	"github.com/meili-NG/meiliNG/v2/pkg/geoip"
)

// hookExt exercises every server hook. It is registered once per test binary
// (the ext registry is global) and only adds a header, a private route, and a
// /health route that core must keep winning, so it cannot disturb other tests.
type hookExt struct {
	initialized atomic.Int32
	shutdowns   atomic.Int32
}

func (*hookExt) Name() string { return "meiling-test-hooks" }

func (e *hookExt) Init(context.Context, ext.Host) error {
	e.initialized.Add(1)
	return nil
}

func (*hookExt) Middleware(ext.Host) []fiber.Handler {
	return []fiber.Handler{func(c *fiber.Ctx) error {
		c.Set("X-Meiling-Test-Ext", "1")
		return c.Next()
	}}
}

func (*hookExt) RegisterRoutes(app *fiber.App, host ext.Host) error {
	name := host.Config().InstanceConfig.Name
	app.Get("/meiling-test-ext/ping", func(c *fiber.Ctx) error {
		return c.SendString("pong from " + name)
	})
	// Core registers /health first, so this must never be reached.
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusInternalServerError)
	})
	return nil
}

func (e *hookExt) Shutdown(context.Context) error {
	e.shutdowns.Add(1)
	return nil
}

var (
	testHooks     = &hookExt{}
	testHooksOnce sync.Once
)

func TestExtensionServerHooks(t *testing.T) {
	testHooksOnce.Do(func() { ext.Register(testHooks) })
	before := testHooks.initialized.Load()

	env := newFeatureEnv(t)

	if testHooks.initialized.Load() != before+1 {
		t.Fatal("Initializer did not run during startup")
	}

	resp, err := env.server.Test(httptest.NewRequest(http.MethodGet, "/meiling-test-ext/ping", nil))
	if err != nil {
		t.Fatalf("GET ping: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "pong from Meiling Test" {
		t.Fatalf("extension route = %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Meiling-Test-Ext") != "1" {
		t.Fatal("extension middleware did not run")
	}

	health, err := env.server.Test(httptest.NewRequest(http.MethodGet, "/health", nil))
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	if health.StatusCode != http.StatusOK {
		t.Fatalf("/health = %d, extension route shadowed core", health.StatusCode)
	}

	shutdowns := testHooks.shutdowns.Load()
	if err := env.app.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if testHooks.shutdowns.Load() != shutdowns+1 {
		t.Fatal("Shutdowner did not run on Shutdown")
	}
}

// TestGeoIPResolverPrecedence proves the instance gets its lookup from
// geoip.Provider, built from its own config, and that a per-instance
// SetGeoIPResolver still wins.
func TestGeoIPResolverPrecedence(t *testing.T) {
	t.Cleanup(geoip.Provider.Reset)
	geoip.Provider.Override(func(cfg *config.MeilingConfig) (geoip.ResolveFunc, error) {
		code := cfg.InstanceConfig.Name
		return func(string) (*geoip.Result, error) {
			return &geoip.Result{CountryCode: code}, nil
		}, nil
	})
	env := newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) {
		cfg.InstanceConfig.Name = "ZZ"
	})
	resolve := database.GetDependencies().ResolveGeoIP

	if got, err := resolve("192.0.2.1"); err != nil || got == nil || got.CountryCode != "ZZ" {
		t.Fatalf("geoip.Provider lookup not used: got %+v, %v", got, err)
	}

	env.app.SetGeoIPResolver(func(string) (*geoip.Result, error) {
		return &geoip.Result{CountryCode: "NZ"}, nil
	})
	if got, err := resolve("192.0.2.1"); err != nil || got == nil || got.CountryCode != "NZ" {
		t.Fatalf("instance resolver did not take precedence: got %+v, %v", got, err)
	}
}
