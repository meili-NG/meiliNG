// Package auth holds the sign-in extension points. A distribution replaces
// them from init() to bring its own logic, and auth.signin in the config
// switches built-in behavior on and off:
//
//   - IdentifierResolver turns what a user typed into a user, e.g. to also
//     accept phone numbers or employee IDs.
//   - SignInPolicy decides, after the user passed their authenticators,
//     whether the sign-in goes ahead, e.g. to demand a second factor from an
//     unfamiliar country.
//   - pkg/auth/password verifies stored passwords by scheme, e.g. against a
//     directory server.
package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// Built-in authenticator types, the names auth.signin.disabledMethods takes.
const (
	MethodPassword   = "password"
	MethodWebAuthn   = "webauthn"
	MethodTOTP       = "totp"
	MethodBackupCode = database.BackupCodeType
	MethodPGP        = database.PGPKeyType
	MethodSSH        = database.SSHKeyType
)

var builtinMethods = []string{MethodPassword, MethodWebAuthn, MethodTOTP, MethodBackupCode, MethodPGP, MethodSSH}

// MethodEnabled reports whether authenticators of type method may be used to
// sign in.
func MethodEnabled(cfg *config.MeilingConfig, method string) bool {
	return !slices.Contains(cfg.AuthConfig.SignIn.DisabledMethods, method)
}

// PasskeyEnabled reports whether a passkey alone, without an identifier, can
// start a sign-in.
func PasskeyEnabled(cfg *config.MeilingConfig) bool {
	return !cfg.AuthConfig.SignIn.DisablePasskey && MethodEnabled(cfg, MethodWebAuthn)
}

// ValidateConfig rejects auth.signin settings that name an unknown method or
// leave no way to sign in.
func ValidateConfig(cfg *config.MeilingConfig) error {
	in := cfg.AuthConfig.SignIn
	for _, method := range in.DisabledMethods {
		if !slices.Contains(builtinMethods, method) {
			return fmt.Errorf("auth.signin.disabledMethods: unknown method %q (known: %v)", method, builtinMethods)
		}
	}
	if !slices.ContainsFunc([]string{MethodPassword, MethodWebAuthn, MethodPGP, MethodSSH}, func(m string) bool { return MethodEnabled(cfg, m) }) {
		return errors.New("auth.signin.disabledMethods: every first-factor method is disabled, so nobody can sign in")
	}
	// A replaced resolver may accept other identifiers.
	if in.DisableUsername && in.DisableEmail && !PasskeyEnabled(cfg) && !IdentifierResolver.Overridden() {
		return errors.New("auth.signin: usernames, email addresses and passkeys are all disabled, so nobody can sign in")
	}
	return nil
}

// IdentifierResolverFunc returns the user identifier names, or uuid.Nil when
// it names nobody.
type IdentifierResolverFunc func(ctx context.Context, cfg *config.MeilingConfig, identifier string) (uuid.UUID, error)

// IdentifierResolver finds the user a sign-in starts for. Its default is
// ResolveIdentifier; an override can fall back to IdentifierResolver.Default().
var IdentifierResolver = ext.NewSlot[IdentifierResolverFunc](ResolveIdentifier)

// ResolveIdentifier accepts a username or an email address, as
// auth.signin allows.
func ResolveIdentifier(_ context.Context, cfg *config.MeilingConfig, identifier string) (uuid.UUID, error) {
	in := cfg.AuthConfig.SignIn
	user, err := (&database.UserFinder{}).FindBySignInIdentifier(identifier, database.SignInLookup{
		Username:        !in.DisableUsername,
		Email:           !in.DisableEmail,
		UnverifiedEmail: !in.RequireVerifiedEmail,
	})
	if err != nil || user == nil {
		return uuid.Nil, err
	}
	return user.ID, nil
}

// SignInAttempt is a sign-in whose authenticators all passed.
type SignInAttempt struct {
	UserID uuid.UUID
	// TwoFactorEnabled is whether the user turned on two-factor sign-in.
	TwoFactorEnabled bool
	// Methods are the authenticator types passed.
	Methods []string
	// PassedTwoFactor is whether a second factor, or a passwordless
	// authenticator, was passed.
	PassedTwoFactor bool

	IP          string
	Country     string
	CountryCode string
	UserAgent   string
}

// ErrTwoFactorRequired, returned by a SignInPolicyFunc, asks the user for a
// second factor instead of refusing the sign-in.
var ErrTwoFactorRequired = errors.New("auth: a second factor is required")

// SignInPolicyFunc returns nil to let a sign-in through, ErrTwoFactorRequired
// to ask for a second factor, or another error to refuse it.
type SignInPolicyFunc func(ctx context.Context, cfg *config.MeilingConfig, attempt SignInAttempt) error

// SignInPolicy runs before a session is signed in. Its default is
// DefaultSignInPolicy; an override can call SignInPolicy.Default() first.
var SignInPolicy = ext.NewSlot[SignInPolicyFunc](DefaultSignInPolicy)

// DefaultSignInPolicy asks for a second factor from users who turned it on,
// or from everyone under auth.signin.requireTwoFactor.
func DefaultSignInPolicy(_ context.Context, cfg *config.MeilingConfig, attempt SignInAttempt) error {
	if !attempt.PassedTwoFactor && (attempt.TwoFactorEnabled || cfg.AuthConfig.SignIn.RequireTwoFactor) {
		return ErrTwoFactorRequired
	}
	return nil
}

// ACR values: whether the user passed one factor or more, a passwordless
// authenticator counting as more.
const (
	ACRSingleFactor = "1fa"
	ACRMultiFactor  = "2fa"
)

// amrOf maps authenticator types to RFC 8176 amr values.
var amrOf = map[string]string{
	MethodPassword:   "pwd",
	MethodTOTP:       "otp",
	MethodBackupCode: "otp",
	MethodWebAuthn:   "hwk",
	MethodPGP:        "swk",
	MethodSSH:        "swk",
}

// Context returns how the user with userID signed into session, or nil when
// there is no session or it has no record of that user.
func Context(session *tokens.SessionPayload, userID string) *tokens.AuthContext {
	if session == nil {
		return nil
	}
	signIn, ok := session.Auth[userID]
	if !ok {
		return nil
	}

	ctx := &tokens.AuthContext{SID: session.SID, AuthTime: signIn.Time, ACR: ACRSingleFactor}
	for _, method := range signIn.Methods {
		if amr, ok := amrOf[method]; ok && !slices.Contains(ctx.AMR, amr) {
			ctx.AMR = append(ctx.AMR, amr)
		}
	}
	if signIn.TwoFactor {
		ctx.ACR = ACRMultiFactor
		if len(ctx.AMR) > 1 {
			ctx.AMR = append(ctx.AMR, "mfa")
		}
	}
	return ctx
}

// ReauthenticationRequired reports whether ctx falls short of an authorization
// request: the sign-in is older than maxAge seconds (negative for no limit), or
// weaker than acrValues, a space-delimited list of acceptable acr values.
func ReauthenticationRequired(ctx *tokens.AuthContext, maxAge int, acrValues string, now time.Time) bool {
	wanted := strings.Fields(acrValues)
	if maxAge < 0 && len(wanted) == 0 {
		return false
	}
	if ctx == nil {
		return true
	}
	if maxAge >= 0 && now.Unix()-ctx.AuthTime > int64(maxAge) {
		return true
	}
	// 2fa satisfies a request that also accepts 1fa.
	if len(wanted) > 0 && !slices.Contains(wanted, ctx.ACR) && !(ctx.ACR == ACRMultiFactor && slices.Contains(wanted, ACRSingleFactor)) {
		return true
	}
	return false
}

// Client is an application a ClientPolicy decides on.
type Client struct {
	ApplicationID uuid.UUID
	// BypassConsent is the application's own bypass_consent setting.
	BypassConsent bool
}

// ClientPolicy decides what an application may do beyond core's rules. A
// distribution replaces it, e.g. to trust applications it marks in their
// metadata (pkg/metadata).
type ClientPolicy struct {
	// BypassConsent reports whether the application may skip the consent
	// screen with prompt=bypass, when oauth2.enablePromptBypass allows it.
	BypassConsent func(ctx context.Context, client Client) bool
	// IntrospectAny reports whether the application may introspect tokens
	// issued to other applications; every application may its own.
	IntrospectAny func(ctx context.Context, client Client) bool
}

// Clients is the active ClientPolicy. Its default trusts only an
// application's bypass_consent setting and lets no application introspect
// another's tokens.
var Clients = ext.NewSlot(ClientPolicy{
	BypassConsent: func(_ context.Context, client Client) bool { return client.BypassConsent },
	IntrospectAny: func(context.Context, Client) bool { return false },
})
