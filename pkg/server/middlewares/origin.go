package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
)

// ValidateFrontendOrigins checks if the request origin is allowed
func ValidateFrontendOrigins(cfg *config.MeilingConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := validateFrontendOrigins(cfg, c); err != nil {
			return err
		}
		return c.Next()
	}
}

// validateFrontendOrigins rejects browser requests from origins outside
// server.frontendOrigins, using the same match as CORS. Requests without an
// Origin header, such as server-to-server calls, pass.
func validateFrontendOrigins(cfg *config.MeilingConfig, c *fiber.Ctx) error {
	if origin := c.Get("Origin"); origin != "" && !cfg.ServerConfig.AllowsOrigin(origin) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "origin is not allowed")
	}
	return nil
}
