package telemetry

import (
	"context"
	"fmt"

	"github.com/gofiber/contrib/otelfiber/v2"
	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// OTelSection is where OTelConfig is read from.
const OTelSection = "telemetry.otel"

// OTelConfig enables OpenTelemetry tracing of HTTP requests, exported over
// OTLP/HTTP. The exporter also honors the standard OTEL_* environment
// variables (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_HEADERS,
// OTEL_SERVICE_NAME, ...).
type OTelConfig struct {
	Enabled bool `json:"enabled" default:"false"`
	// Endpoint is the OTLP/HTTP collector URL, such as
	// http://localhost:4318. Empty leaves it to OTEL_EXPORTER_OTLP_ENDPOINT,
	// or the exporter's default of localhost:4318.
	Endpoint string `json:"endpoint"`
}

func init() { config.RegisterSection[OTelConfig](OTelSection) }

func startOTel(cfg *config.MeilingConfig) (*Reporter, error) {
	c, _ := config.Section[OTelConfig](cfg, OTelSection)
	if !c.Enabled {
		return nil, nil
	}
	ctx := context.Background()
	var opts []otlptracehttp.Option
	if c.Endpoint != "" {
		opts = append(opts, otlptracehttp.WithEndpointURL(c.Endpoint))
	}
	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otel: %w", err)
	}
	// Later options win, so OTEL_SERVICE_NAME overrides instance.name.
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(cfg.InstanceConfig.Name)),
		resource.WithFromEnv(),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: %w", err)
	}
	// The provider is per instance, not the process-wide global.
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(res))
	return &Reporter{
		Middleware: []fiber.Handler{otelfiber.Middleware(
			otelfiber.WithTracerProvider(provider),
			otelfiber.WithPropagators(propagation.TraceContext{}),
		)},
		Shutdown: provider.Shutdown,
	}, nil
}
