package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// Config sections of the built-in providers.
const (
	TurnstileSection = "captcha.turnstile"
	RecaptchaSection = "captcha.recaptcha"
)

// TurnstileConfig enables Cloudflare Turnstile.
type TurnstileConfig struct {
	Enabled bool   `json:"enabled" default:"false"`
	Secret  string `json:"secret"`
	// SiteKey is the public key clients render the widget with. It is
	// published by GET /v2/instance.
	SiteKey string `json:"siteKey"`
}

// RecaptchaConfig enables Google reCAPTCHA, v2 or v3.
type RecaptchaConfig struct {
	Enabled bool   `json:"enabled" default:"false"`
	Secret  string `json:"secret"`
	// SiteKey is the public key clients render the widget with. It is
	// published by GET /v2/instance.
	SiteKey string `json:"siteKey"`
	// MinScore rejects v3 responses scoring below it. v2 responses carry no
	// score and are unaffected.
	MinScore float64 `json:"minScore" default:"0.5"`
}

func init() {
	config.RegisterSection[TurnstileConfig](TurnstileSection)
	config.RegisterSection[RecaptchaConfig](RecaptchaSection)
}

var siteverifyURLs = map[string]string{
	"turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	"recaptcha": "https://www.google.com/recaptcha/api/siteverify",
}

// Builtin is Provider's default. It returns the Turnstile or reCAPTCHA
// verifier, whichever is enabled, or none.
func Builtin(cfg *config.MeilingConfig) (Verifier, error) {
	t, _ := config.Section[TurnstileConfig](cfg, TurnstileSection)
	r, _ := config.Section[RecaptchaConfig](cfg, RecaptchaSection)
	switch {
	case t.Enabled && r.Enabled:
		return nil, errors.New("enable only one of turnstile and recaptcha")
	case t.Enabled:
		if t.Secret == "" {
			return nil, errors.New("captcha.turnstile.secret is required when captcha.turnstile.enabled is set")
		}
		return siteverify{provider: "turnstile", url: siteverifyURLs["turnstile"], secret: t.Secret, siteKey: t.SiteKey}, nil
	case r.Enabled:
		if r.Secret == "" {
			return nil, errors.New("captcha.recaptcha.secret is required when captcha.recaptcha.enabled is set")
		}
		return siteverify{provider: "recaptcha", url: siteverifyURLs["recaptcha"], secret: r.Secret, siteKey: r.SiteKey, minScore: r.MinScore}, nil
	}
	return nil, nil
}

var siteverifyClient = &http.Client{Timeout: 10 * time.Second}

// siteverify speaks the verification protocol Turnstile and reCAPTCHA share:
// a form POST of secret, response and remoteip, answered with JSON.
type siteverify struct {
	provider, url, secret, siteKey string
	minScore                       float64
}

func (v siteverify) Widget() Widget {
	return Widget{Provider: v.provider, SiteKey: v.siteKey}
}

func (v siteverify) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	form := url.Values{"secret": {v.secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := siteverifyClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("%s siteverify: %w", v.provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("%s siteverify: HTTP %d", v.provider, resp.StatusCode)
	}
	var out struct {
		Success bool     `json:"success"`
		Score   *float64 `json:"score"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return false, fmt.Errorf("%s siteverify: %w", v.provider, err)
	}
	// A v3 reCAPTCHA token is "successful" whatever its score; the score
	// decides.
	if out.Score != nil && *out.Score < v.minScore {
		return false, nil
	}
	return out.Success, nil
}
