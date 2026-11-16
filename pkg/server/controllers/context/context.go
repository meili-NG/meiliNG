package context

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// Context keys for storing values
type contextKey string

const (
	principalKey   contextKey = "principal"
	userKey        contextKey = "user"
	applicationKey contextKey = "application"
	fiberKey       contextKey = "fiber"
)

// Principal context helpers

// WithPrincipal adds the authenticated caller to the context.
func WithPrincipal(ctx context.Context, principal *tokens.Principal) context.Context {
	return context.WithValue(ctx, principalKey, principal)
}

// GetPrincipal returns the authenticated caller, or nil.
func GetPrincipal(ctx context.Context) *tokens.Principal {
	if principal, ok := ctx.Value(principalKey).(*tokens.Principal); ok {
		return principal
	}
	return nil
}

// WithFiberCtx adds the active Fiber context to the request context.
func WithFiberCtx(ctx context.Context, c *fiber.Ctx) context.Context {
	return context.WithValue(ctx, fiberKey, c)
}

// GetFiberCtx retrieves the active Fiber context from the request context.
func GetFiberCtx(ctx context.Context) *fiber.Ctx {
	if c, ok := ctx.Value(fiberKey).(*fiber.Ctx); ok {
		return c
	}
	return nil
}

// RequirePrincipal returns the authenticated caller or an error.
func RequirePrincipal(ctx context.Context) (*tokens.Principal, error) {
	if principal := GetPrincipal(ctx); principal != nil {
		return principal, nil
	}
	return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session not found")
}

// WithUser adds the selected user to the context.
func WithUser(ctx context.Context, user *api.SelectedUser) context.Context {
	return context.WithValue(ctx, userKey, user)
}

// GetUser retrieves the selected user from context.
func GetUser(ctx context.Context) *api.SelectedUser {
	if user, ok := ctx.Value(userKey).(*api.SelectedUser); ok {
		return user
	}
	return nil
}

// WithApplication adds the selected application to the context.
func WithApplication(ctx context.Context, application *api.SelectedApplication) context.Context {
	return context.WithValue(ctx, applicationKey, application)
}

// GetApplication retrieves the selected application from context.
func GetApplication(ctx context.Context) *api.SelectedApplication {
	if application, ok := ctx.Value(applicationKey).(*api.SelectedApplication); ok {
		return application
	}
	return nil
}

// RequireAdmin checks that the caller is an admin credential.
func RequireAdmin(ctx context.Context) error {
	principal, err := RequirePrincipal(ctx)
	if err != nil {
		return err
	}
	if !principal.IsAdmin() {
		return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "admin privileges required")
	}
	return nil
}

// IsAdmin reports whether the caller is an admin credential.
func IsAdmin(ctx context.Context) bool {
	return GetPrincipal(ctx).IsAdmin()
}
