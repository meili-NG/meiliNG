// Package telemetry reports errors and traces to an external service. Sentry
// and OpenTelemetry are built in and off until configured (see Builtin); a
// distribution can supply another reporter through Provider.
package telemetry

import (
	"context"

	"github.com/gofiber/fiber/v2"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
)

// Reporter is what a provider plugs into the server. Both fields are
// optional.
type Reporter struct {
	// Middleware runs first on every request, before the server's own middleware.
	Middleware []fiber.Handler
	// Shutdown delivers what is still queued. It runs after the HTTP server
	// has stopped.
	Shutdown func(ctx context.Context) error
}

// ProviderFunc starts reporting for an instance from its config. Returning a
// nil Reporter means nothing is reported; an error fails startup.
type ProviderFunc func(cfg *config.MeilingConfig) (*Reporter, error)

// Provider supplies the reporter. It defaults to Builtin; a distribution
// replaces it to report elsewhere:
//
//	func init() { telemetry.Provider.Override(myProvider) }
var Provider = ext.NewSlot[ProviderFunc](Builtin)

// Builtin is Provider's default. It starts Sentry, OpenTelemetry, both or
// neither, as configured.
func Builtin(cfg *config.MeilingConfig) (*Reporter, error) {
	var out *Reporter
	for _, start := range []ProviderFunc{startSentry, startOTel} {
		r, err := start(cfg)
		if err != nil {
			return nil, err
		}
		if r == nil {
			continue
		}
		if out == nil {
			out = r
			continue
		}
		first, second := out.Shutdown, r.Shutdown
		out = &Reporter{
			Middleware: append(out.Middleware, r.Middleware...),
			Shutdown: func(ctx context.Context) error {
				err := first(ctx)
				if err2 := second(ctx); err == nil {
					err = err2
				}
				return err
			},
		}
	}
	return out, nil
}
