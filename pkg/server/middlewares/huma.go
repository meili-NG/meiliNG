package middleware

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	mctx "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/context"
)

func writeHumaMiddlewareError(ctx huma.Context, err error) {
	c := humafiber.Unwrap(ctx)
	_ = c.App().Config().ErrorHandler(c, err)
}

// HumaValidateFrontendOrigins validates allowed frontend origins in Huma middleware.
func HumaValidateFrontendOrigins(cfg *config.MeilingConfig) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		c := humafiber.Unwrap(ctx)
		c.SetUserContext(mctx.WithFiberCtx(c.UserContext(), c))
		if err := validateFrontendOrigins(cfg, c); err != nil {
			writeHumaMiddlewareError(ctx, err)
			return
		}
		next(huma.WithContext(ctx, c.UserContext()))
	}
}

// HumaCheckSession validates a session in Huma middleware and stores it in the Fiber context.
func HumaCheckSession(a *app.Meiling) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		c := humafiber.Unwrap(ctx)
		c.SetUserContext(mctx.WithFiberCtx(c.UserContext(), c))
		if err := validateSession(a, c); err != nil {
			writeHumaMiddlewareError(ctx, err)
			return
		}
		next(huma.WithContext(ctx, c.UserContext()))
	}
}

// HumaCheckAdmin enforces admin authorization in Huma middleware.
func HumaCheckAdmin(a *app.Meiling) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		c := humafiber.Unwrap(ctx)
		if err := validateAdmin(a, c); err != nil {
			writeHumaMiddlewareError(ctx, err)
			return
		}
		next(huma.WithContext(ctx, c.UserContext()))
	}
}

// HumaSelectUserFromSession loads the current user from the session in Huma middleware.
func HumaSelectUserFromSession(action string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		c := humafiber.Unwrap(ctx)
		if err := selectUserFromSession(c, action); err != nil {
			writeHumaMiddlewareError(ctx, err)
			return
		}
		next(huma.WithContext(ctx, c.UserContext()))
	}
}

// HumaFetchApplication loads the application into the Fiber context.
func HumaFetchApplication() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		c := humafiber.Unwrap(ctx)
		if err := fetchApplication(c); err != nil {
			writeHumaMiddlewareError(ctx, err)
			return
		}
		next(huma.WithContext(ctx, c.UserContext()))
	}
}

// HumaCheckApplicationOwnership ensures the current user owns the loaded application.
func HumaCheckApplicationOwnership() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		c := humafiber.Unwrap(ctx)
		if err := checkApplicationOwnership(c); err != nil {
			writeHumaMiddlewareError(ctx, err)
			return
		}
		next(ctx)
	}
}

// HumaValidateApplicationOwnership validates that the current user owns the loaded application.
func HumaValidateApplicationOwnership(userIDLocation string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		c := humafiber.Unwrap(ctx)
		if err := validateApplicationOwnership(c, userIDLocation); err != nil {
			writeHumaMiddlewareError(ctx, err)
			return
		}
		next(ctx)
	}
}
