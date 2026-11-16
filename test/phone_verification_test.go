package test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/notify"
)

// phoneNotifier stands in for a vendor SMS provider: it handles only the phone key.
type phoneNotifier struct {
	mu        sync.Mutex
	recipient string
	code      string
}

func (*phoneNotifier) Name() string { return "test-phone-notifier" }
func (*phoneNotifier) Supports(key notify.NotifyKey) bool {
	return key == notify.NotifyKeyPhoneVerificationCode
}
func (p *phoneNotifier) Notify(_ context.Context, _ *config.MeilingConfig, n notify.Notification) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recipient, p.code = n.Recipient, n.Args.String("code")
	return nil
}

var testPhoneNotifier = &phoneNotifier{}

func init() { notify.Register(testPhoneNotifier) }

func TestPhoneVerificationGoesThroughTheMappedProvider(t *testing.T) {
	t.Run("unavailable without a provider", func(t *testing.T) {
		env := newFeatureEnv(t)
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/verify", map[string]any{"phone": "+1 202-555-0123"}, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotImplemented)
		}
	})

	t.Run("sent and verified with a mapped provider", func(t *testing.T) {
		env := newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) {
			cfg.NotificationConfig.Keys = map[string]string{string(notify.NotifyKeyPhoneVerificationCode): testPhoneNotifier.Name()}
		})

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/verify", map[string]any{"phone": "+1 202-555-0123"}, nil)
		var issued types.SignUpTokenResponse
		decodeJSONBody(t, resp, &issued)
		if resp.StatusCode != http.StatusOK || issued.Token == "" {
			t.Fatalf("request status = %d, token = %q", resp.StatusCode, issued.Token)
		}

		testPhoneNotifier.mu.Lock()
		recipient, code := testPhoneNotifier.recipient, testPhoneNotifier.code
		testPhoneNotifier.mu.Unlock()
		if recipient != "+12025550123" || len(code) != 6 {
			t.Fatalf("provider got recipient %q code %q, want the E.164 number and a 6-digit code", recipient, code)
		}

		verify := func(response string) int {
			resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/verify", map[string]any{
				"phone": "+1 (202) 555-0123", "ownershipToken": issued.Token, "response": response,
			}, nil)
			resp.Body.Close()
			return resp.StatusCode
		}
		if status := verify("not-the-code"); status == http.StatusOK {
			t.Fatalf("wrong code was accepted")
		}
		if status := verify(code); status != http.StatusOK {
			t.Fatalf("verify status = %d, want %d", status, http.StatusOK)
		}

		got, err := env.app.TokenServices().Ownership().Get(issued.Token)
		if err != nil || !got.PhoneVerified {
			t.Fatalf("ownership token phone verified = %v (err %v), want true", got.PhoneVerified, err)
		}
	})
}
