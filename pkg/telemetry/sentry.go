package telemetry

import (
	"context"
	"errors"
	"fmt"
	"time"

	sentrygo "github.com/getsentry/sentry-go"
	sentryfiber "github.com/getsentry/sentry-go/fiber"
	"github.com/gofiber/fiber/v2"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// SentrySection is where SentryConfig is read from.
const SentrySection = "telemetry.sentry"

// SentryConfig enables Sentry.
type SentryConfig struct {
	Enabled bool   `json:"enabled" default:"false"`
	DSN     string `json:"dsn"`
}

// sentryFlushTimeout bounds how long shutdown waits for queued events.
const sentryFlushTimeout = 2 * time.Second

func init() { config.RegisterSection[SentryConfig](SentrySection) }

// startSentry starts the Sentry client. The client is process-wide, so the
// last instance started with Sentry enabled decides where events go.
func startSentry(cfg *config.MeilingConfig) (*Reporter, error) {
	c, _ := config.Section[SentryConfig](cfg, SentrySection)
	if !c.Enabled {
		return nil, nil
	}
	if c.DSN == "" {
		return nil, errors.New("telemetry.sentry.dsn is required when telemetry.sentry.enabled is set")
	}
	err := sentrygo.Init(sentrygo.ClientOptions{
		Dsn:           c.DSN,
		EnableTracing: true,
		// Capture every transaction for tracing.
		TracesSampleRate: 1.0,
		EnableLogs:       true,
	})
	if err != nil {
		return nil, fmt.Errorf("sentry: %w", err)
	}
	return &Reporter{
		// Reports panics and attaches a per-request hub.
		Middleware: []fiber.Handler{sentryfiber.New(sentryfiber.Options{
			Repanic:         true,
			WaitForDelivery: false,
		})},
		Shutdown: func(context.Context) error {
			sentrygo.Flush(sentryFlushTimeout)
			return nil
		},
	}, nil
}
