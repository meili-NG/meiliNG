package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestBuiltinIsOffUntilEnabled(t *testing.T) {
	cfg := &config.MeilingConfig{}
	if r, err := Builtin(cfg); err != nil || r != nil {
		t.Fatalf("Builtin unconfigured = %v, %v; want off", r, err)
	}

	cfg.SetSection(SentrySection, SentryConfig{Enabled: true})
	if _, err := Builtin(cfg); err == nil {
		t.Fatal("sentry enabled without a DSN succeeded, want an error")
	}
}

func TestOTelExportsRequestSpans(t *testing.T) {
	exported := make(chan struct{}, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/v1/traces" {
			select {
			case exported <- struct{}{}:
			default:
			}
		}
	}))
	defer collector.Close()

	cfg := &config.MeilingConfig{}
	cfg.InstanceConfig.Name = "test"
	cfg.SetSection(OTelSection, OTelConfig{Enabled: true, Endpoint: collector.URL})
	r, err := Builtin(cfg)
	if err != nil || r == nil || len(r.Middleware) != 1 {
		t.Fatalf("Builtin with otel = %v, %v", r, err)
	}

	app := fiber.New()
	app.Use(r.Middleware[0])
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })
	if _, err := app.Test(httptest.NewRequest(http.MethodGet, "/", nil)); err != nil {
		t.Fatal(err)
	}
	// Shutdown flushes the batch.
	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case <-exported:
	default:
		t.Fatal("no span reached the collector")
	}
}
