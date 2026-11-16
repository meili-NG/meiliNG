package tokens

import (
	"strings"
	"testing"
	"time"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
)

type runtimeTestPayload struct {
	GlobalTokenPayload
	Label string `json:"label"`
}

func newRuntimeTestServices(t *testing.T) *Services {
	t.Helper()

	dir := t.TempDir()
	privateKeyPath, publicKeyPath := generateRSAKeyPairForTest(t, dir, "runtime")

	return NewServices(&config.MeilingConfig{
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:      "RS256",
			Issuer:         "https://issuer.example.com",
			PrivateKeyPath: privateKeyPath,
			PublicKeyPath:  publicKeyPath,
		}},
	})
}

func TestManagedTokenManagerNewSetsExpiryAndRoundTrips(t *testing.T) {
	t.Parallel()

	manager := newManagedTokenManager[runtimeTestPayload](newRuntimeTestServices(t), "runtime_test_token", time.Hour)

	token, err := manager.New(runtimeTestPayload{Label: "alpha"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	payload, err := manager.Get(token)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if payload.Label != "alpha" {
		t.Fatalf("Label = %q, want alpha", payload.Label)
	}

	remaining := time.Until(payload.ExpiresAt)
	if remaining < 59*time.Minute || remaining > time.Hour+time.Minute {
		t.Fatalf("ExpiresAt remaining = %s, want about 1h", remaining)
	}

	payload.Label = "beta"
	if err := manager.Set(token, payload); err != nil {
		t.Fatalf("Set: %v", err)
	}

	updated, err := manager.Get(token)
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if updated.Label != "beta" {
		t.Fatalf("updated Label = %q, want beta", updated.Label)
	}
}

func TestManagedTokenManagerNewLeavesExpiryUnsetWhenDisabled(t *testing.T) {
	t.Parallel()

	manager := newManagedTokenManager[runtimeTestPayload](newRuntimeTestServices(t), "runtime_test_no_expiry", 0)

	token, err := manager.New(runtimeTestPayload{Label: "alpha"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	payload, err := manager.Get(token)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !payload.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt = %s, want zero value", payload.ExpiresAt)
	}
}

func TestManagedTokenManagerRevokeReturnsRevokedErrorOnRepeat(t *testing.T) {
	t.Parallel()

	manager := newManagedTokenManager[runtimeTestPayload](newRuntimeTestServices(t), "runtime_test_revoke", time.Hour)

	token, err := manager.New(runtimeTestPayload{Label: "alpha"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := manager.Revoke(token); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}

	err = manager.Revoke(token)
	if err == nil {
		t.Fatal("second Revoke error = nil, want revoked error")
	}

	meilingErr, ok := err.(*meilingErrors.Error)
	if !ok {
		t.Fatalf("second Revoke error type = %T, want *errors.Error", err)
	}
	if meilingErr.Type != meilingErrors.ErrTokenRevoked {
		t.Fatalf("second Revoke error type = %q, want %q", meilingErr.Type, meilingErrors.ErrTokenRevoked)
	}
	if !strings.Contains(meilingErr.Message, "token has been revoked @") {
		t.Fatalf("second Revoke message = %q", meilingErr.Message)
	}
}
