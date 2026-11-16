package controllers

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	mctx "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/context"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// Base provides common functionality for all controllers.
// Controllers should embed this struct to get access to the Meiling instance.
type Base struct {
	App *app.Meiling
}

// NewBase creates a new Base with the given Meiling instance.
func NewBase(a *app.Meiling) Base {
	return Base{App: a}
}

// Config returns the application configuration.
// This is a convenience method that delegates to App.Config().
func (b *Base) Config() *config.MeilingConfig {
	return b.App.Config()
}

func (b *Base) TokenServices() *tokens.Services {
	return b.App.TokenServices()
}

// RequirePrincipal returns the authenticated caller: a session, or an admin
// credential.
func (b *Base) RequirePrincipal(ctx context.Context) (*tokens.Principal, error) {
	return mctx.RequirePrincipal(ctx)
}

// RequireUserSession returns the caller's session. Admin credentials have
// none, so flows that sign users in or out refuse them.
func (b *Base) RequireUserSession(ctx context.Context) (*tokens.SessionPayload, error) {
	principal, err := mctx.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if principal.Session == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "this needs a session; admin credentials have none")
	}
	return principal.Session, nil
}

func (b *Base) ResolveOptionalPrincipal(ctx context.Context, authorization string) (*tokens.Principal, error) {
	if principal := mctx.GetPrincipal(ctx); principal != nil {
		return principal, nil
	}
	if authorization == "" {
		return nil, nil
	}
	return api.ParseAuthorization(b.Config(), b.TokenServices(), authorization)
}

func (b *Base) ResolveRequiredPrincipal(ctx context.Context, authorization string) (*tokens.Principal, error) {
	principal, err := b.ResolveOptionalPrincipal(ctx, authorization)
	if err != nil {
		return nil, err
	}
	if principal == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session not found")
	}
	return principal, nil
}
