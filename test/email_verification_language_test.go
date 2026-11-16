package test

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/notify"
)

// recordingNotifier keeps the language of every verification code it is asked to deliver.
type recordingNotifier struct {
	mu    sync.Mutex
	langs []string
}

func (*recordingNotifier) Name() string                   { return "test-recording-notifier" }
func (*recordingNotifier) Supports(notify.NotifyKey) bool { return true }
func (r *recordingNotifier) Notify(_ context.Context, _ *config.MeilingConfig, n notify.Notification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.langs = append(r.langs, n.Args.String("lang"))
	return nil
}

var verificationLanguageNotifier = &recordingNotifier{}

func init() { notify.Register(verificationLanguageNotifier) }

func TestEmailVerificationHonoursAcceptLanguage(t *testing.T) {
	env := newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) {
		cfg.NotificationConfig.DefaultProvider = verificationLanguageNotifier.Name()
	})

	username := "verifylang" + uniqueSuffix()
	email := username + "@example.com"
	userID := mustCreateUser(t, env, username, "verify-password-123", email)
	sessionToken := mustCreateSessionToken(t, env)
	mustAttachUserToSession(t, env, sessionToken, userID)

	for acceptLanguage, want := range map[string]string{
		"ko-KR,ko;q=0.9": "ko",
		"ko":             "ko",
		"":               "en",
		"*":              "en",
	} {
		headers := bearerHeaders(sessionToken)
		if acceptLanguage != "" {
			headers["Accept-Language"] = acceptLanguage
		}
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/"+userID+"/emails/verify?email="+url.QueryEscape(email), map[string]any{}, headers)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("verify with Accept-Language %q status = %d, want %d", acceptLanguage, resp.StatusCode, http.StatusOK)
		}

		verificationLanguageNotifier.mu.Lock()
		got := verificationLanguageNotifier.langs[len(verificationLanguageNotifier.langs)-1]
		verificationLanguageNotifier.mu.Unlock()
		if got != want {
			t.Fatalf("Accept-Language %q sent the code in %q, want %q", acceptLanguage, got, want)
		}
	}
}
