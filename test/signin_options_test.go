package test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/pkg/auth"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// passwordSignIn runs the password sign-in flow and returns the status of the
// first step that did not succeed, with its body, or 200 when every step did.
func passwordSignIn(t *testing.T, env *featureEnv, identifier, password string) (int, string) {
	t.Helper()
	headers := bearerHeaders(mustCreateSessionToken(t, env))
	step := func(resp *http.Response) (int, string, bool) {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(raw), resp.StatusCode == http.StatusOK
	}

	resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{"username": identifier}, headers)
	if resp.StatusCode != http.StatusOK {
		status, body, _ := step(resp)
		return status, body
	}
	var started struct {
		RequestToken string `json:"requestToken"`
	}
	decodeJSONBody(t, resp, &started)
	query := "?token=" + url.QueryEscape(started.RequestToken) + "&type=password&for=signin"

	if status, body, ok := step(mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue"+query, nil, nil)); !ok {
		return status, body
	}
	if status, body, ok := step(mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate"+query, map[string]any{"response": password}, nil)); !ok {
		return status, body
	}
	status, body, _ := step(mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{"challengeToken": started.RequestToken}, headers))
	return status, body
}

func TestSignInOptions(t *testing.T) {
	withSignIn := func(t *testing.T, in config.SignInConfig) (*featureEnv, string, string) {
		t.Helper()
		env := newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) { cfg.AuthConfig.SignIn = in })
		username := "signin" + uniqueSuffix()
		mustCreateUser(t, env, username, "signin-password-123", username+"@example.com")
		return env, username, username + "@example.com"
	}

	t.Run("both identifiers by default", func(t *testing.T) {
		env, username, email := withSignIn(t, config.SignInConfig{})
		for _, id := range []string{username, email} {
			if status, body := passwordSignIn(t, env, id, "signin-password-123"); status != http.StatusOK {
				t.Fatalf("sign in as %q = %d %s", id, status, body)
			}
		}
	})

	t.Run("disableUsername", func(t *testing.T) {
		env, username, email := withSignIn(t, config.SignInConfig{DisableUsername: true})
		if status, _ := passwordSignIn(t, env, username, "signin-password-123"); status != http.StatusNotFound {
			t.Fatalf("username sign-in = %d, want 404", status)
		}
		if status, body := passwordSignIn(t, env, email, "signin-password-123"); status != http.StatusOK {
			t.Fatalf("email sign-in = %d %s", status, body)
		}
	})

	t.Run("disableEmail", func(t *testing.T) {
		env, username, email := withSignIn(t, config.SignInConfig{DisableEmail: true})
		if status, _ := passwordSignIn(t, env, email, "signin-password-123"); status != http.StatusNotFound {
			t.Fatalf("email sign-in = %d, want 404", status)
		}
		if status, body := passwordSignIn(t, env, username, "signin-password-123"); status != http.StatusOK {
			t.Fatalf("username sign-in = %d %s", status, body)
		}
	})

	t.Run("disabledMethods", func(t *testing.T) {
		env, username, _ := withSignIn(t, config.SignInConfig{DisabledMethods: []string{auth.MethodPassword}})
		if status, _ := passwordSignIn(t, env, username, "signin-password-123"); status == http.StatusOK {
			t.Fatal("password sign-in succeeded with password disabled")
		}
	})

	t.Run("requireTwoFactor", func(t *testing.T) {
		env, username, _ := withSignIn(t, config.SignInConfig{RequireTwoFactor: true})
		if status, body := passwordSignIn(t, env, username, "signin-password-123"); status != http.StatusUnauthorized || !strings.Contains(body, "two_factor_required") {
			t.Fatalf("password-only sign-in = %d %s, want two_factor_required", status, body)
		}
	})

	t.Run("disablePasskey", func(t *testing.T) {
		env, _, _ := withSignIn(t, config.SignInConfig{DisablePasskey: true})
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{"useWebAuthn": true}, bearerHeaders(mustCreateSessionToken(t, env)))
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("passkey sign-in = %d, want 403", resp.StatusCode)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/instance", nil, nil)
		var info struct {
			SignIn struct{ Username, Email, Passkey bool } `json:"signIn"`
		}
		decodeJSONBody(t, resp, &info)
		if !info.SignIn.Username || !info.SignIn.Email || info.SignIn.Passkey {
			t.Fatalf("/v2/instance signIn = %+v", info.SignIn)
		}
	})
}

// A distribution swaps the identifier lookup and the sign-in policy.
func TestSignInExtensionPoints(t *testing.T) {
	env := newFeatureEnv(t)
	username := "plugged" + uniqueSuffix()
	userID := uuid.MustParse(mustCreateUser(t, env, username, "plugged-password-123", username+"@example.com"))

	t.Cleanup(auth.IdentifierResolver.Reset)
	auth.IdentifierResolver.Override(func(ctx context.Context, cfg *config.MeilingConfig, identifier string) (uuid.UUID, error) {
		if identifier == "EMP-1" {
			return userID, nil
		}
		return auth.IdentifierResolver.Default()(ctx, cfg, identifier)
	})
	if status, body := passwordSignIn(t, env, "EMP-1", "plugged-password-123"); status != http.StatusOK {
		t.Fatalf("sign in with a resolver-only identifier = %d %s", status, body)
	}
	if status, body := passwordSignIn(t, env, username, "plugged-password-123"); status != http.StatusOK {
		t.Fatalf("the default lookup behind the override = %d %s", status, body)
	}

	t.Cleanup(auth.SignInPolicy.Reset)
	var seen auth.SignInAttempt
	auth.SignInPolicy.Override(func(ctx context.Context, cfg *config.MeilingConfig, a auth.SignInAttempt) error {
		seen = a
		return errors.New("blocked by policy")
	})
	if status, _ := passwordSignIn(t, env, username, "plugged-password-123"); status != http.StatusForbidden {
		t.Fatalf("sign-in refused by the policy = %d, want 403", status)
	}
	if seen.UserID != userID || len(seen.Methods) != 1 || seen.Methods[0] != auth.MethodPassword {
		t.Fatalf("policy saw %+v", seen)
	}

	auth.SignInPolicy.Override(func(context.Context, *config.MeilingConfig, auth.SignInAttempt) error {
		return auth.ErrTwoFactorRequired
	})
	if status, body := passwordSignIn(t, env, username, "plugged-password-123"); !strings.Contains(body, "two_factor_required") {
		t.Fatalf("policy asking for a second factor = %d %s", status, body)
	}
}

func TestSignInConfigValidation(t *testing.T) {
	for name, in := range map[string]config.SignInConfig{
		"unknown method":     {DisabledMethods: []string{"pasword"}},
		"no sign-in method":  {DisabledMethods: []string{auth.MethodPassword, auth.MethodWebAuthn, auth.MethodPGP, auth.MethodSSH}},
		"no way to identify": {DisableUsername: true, DisableEmail: true, DisablePasskey: true},
	} {
		cfg := &config.MeilingConfig{}
		cfg.AuthConfig.SignIn = in
		if err := auth.ValidateConfig(cfg); err == nil {
			t.Errorf("%s: ValidateConfig accepted %+v", name, in)
		}
	}
	if err := auth.ValidateConfig(&config.MeilingConfig{}); err != nil {
		t.Fatalf("the zero config was rejected: %v", err)
	}
}
