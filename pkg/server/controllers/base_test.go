package controllers

import (
	"context"
	"testing"

	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	mctx "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/context"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

func TestBaseRequireSessionReturnsContextSession(t *testing.T) {
	t.Parallel()

	base := Base{}
	session := tokens.SessionPrincipal(&tokens.SessionPayload{Users: []string{"user-1"}})

	got, err := base.RequirePrincipal(mctx.WithPrincipal(context.Background(), session))
	if err != nil {
		t.Fatalf("RequireSession: %v", err)
	}
	if got != session {
		t.Fatalf("RequireSession returned unexpected session: %#v", got)
	}
}

func TestBaseResolveOptionalSessionUsesContextBeforeAuthorization(t *testing.T) {
	t.Parallel()

	base := Base{}
	session := tokens.SessionPrincipal(&tokens.SessionPayload{Users: []string{"user-1"}})

	got, err := base.ResolveOptionalPrincipal(mctx.WithPrincipal(context.Background(), session), "Bearer ignored")
	if err != nil {
		t.Fatalf("ResolveOptionalSession: %v", err)
	}
	if got != session {
		t.Fatalf("ResolveOptionalSession returned unexpected session: %#v", got)
	}
}

func TestBaseResolveRequiredSessionWithoutSessionReturnsUnauthorized(t *testing.T) {
	t.Parallel()

	base := Base{}

	_, err := base.ResolveRequiredPrincipal(context.Background(), "")
	if err == nil {
		t.Fatal("ResolveRequiredSession error = nil, want unauthorized")
	}

	meilingErr, ok := err.(*meilingErrors.Error)
	if !ok {
		t.Fatalf("ResolveRequiredSession error type = %T, want *errors.Error", err)
	}
	if meilingErr.Type != meilingErrors.ErrUnauthorized {
		t.Fatalf("ResolveRequiredSession error type = %q, want %q", meilingErr.Type, meilingErrors.ErrUnauthorized)
	}
}

// An admin credential has no session, so session-only flows refuse it.
func TestBaseRequireUserSessionRefusesAdmins(t *testing.T) {
	t.Parallel()

	base := Base{}
	admin := &tokens.Principal{Kind: tokens.PrincipalAdminToken, ActorID: "admin_token:00000000"}
	if _, err := base.RequireUserSession(mctx.WithPrincipal(context.Background(), admin)); err == nil {
		t.Fatal("RequireUserSession accepted an admin credential")
	}

	session := &tokens.SessionPayload{Users: []string{"user-1"}}
	got, err := base.RequireUserSession(mctx.WithPrincipal(context.Background(), tokens.SessionPrincipal(session)))
	if err != nil || got != session {
		t.Fatalf("RequireUserSession = %v, %v; want the session", got, err)
	}
}
