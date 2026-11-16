// Package captcha guards endpoints that send codes to an email or phone with a
// bot challenge. Cloudflare Turnstile and Google reCAPTCHA are built in and
// off until configured (see Builtin); a distribution can supply another
// provider through Provider.
package captcha

import (
	"context"
	"fmt"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
)

// Verifier checks a challenge response from a client.
type Verifier interface {
	// Widget tells clients which challenge to render.
	Widget() Widget
	// Verify reports whether token is a valid response. remoteIP is the
	// client address when known, or empty.
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
}

// Widget is the challenge a client renders to obtain a token. GET
// /v2/instance publishes it.
type Widget struct {
	Provider string `json:"provider" doc:"Challenge provider, e.g. turnstile" example:"turnstile"`
	SiteKey  string `json:"siteKey,omitempty" doc:"Public key the provider's client widget needs"`
}

// ProviderFunc builds the verifier for an instance from its config, so a
// provider can read its own config section. Returning a nil Verifier leaves
// challenges off for that instance; an error fails startup.
type ProviderFunc func(cfg *config.MeilingConfig) (Verifier, error)

// Provider supplies the verifier. It defaults to Builtin. A distribution
// replaces it to use another provider, and can fall back to Builtin from its
// own ProviderFunc:
//
//	func init() { captcha.Provider.Override(myProvider) }
var Provider = ext.NewSlot[ProviderFunc](Builtin)

// For returns the verifier for cfg, or nil when challenges are off.
func For(cfg *config.MeilingConfig) (Verifier, error) {
	provide := Provider.Get()
	if provide == nil {
		return nil, nil
	}
	v, err := provide(cfg)
	if err != nil {
		return nil, fmt.Errorf("captcha: %w", err)
	}
	return v, nil
}

// Check verifies token when cfg requires a challenge. It returns nil when
// challenges are off or the token is valid.
func Check(ctx context.Context, cfg *config.MeilingConfig, token, remoteIP string) error {
	v, err := For(cfg)
	if err != nil || v == nil {
		return err
	}
	if token == "" {
		return ErrFailed
	}
	ok, err := v.Verify(ctx, token, remoteIP)
	if err != nil {
		return fmt.Errorf("captcha: %w", err)
	}
	if !ok {
		return ErrFailed
	}
	return nil
}

// ErrFailed is returned by Check for a missing or rejected token.
var ErrFailed = fmt.Errorf("captcha: challenge failed")
