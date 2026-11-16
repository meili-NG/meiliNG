package test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/captcha"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

type fakeVerifier struct{}

func (fakeVerifier) Widget() captcha.Widget {
	return captcha.Widget{Provider: "fake", SiteKey: "site"}
}

func (fakeVerifier) Verify(_ context.Context, token, _ string) (bool, error) {
	return token == "pass", nil
}

// TestCaptchaGuardsOwnershipVerification proves a captcha provider gates
// sending verification codes.
func TestCaptchaGuardsOwnershipVerification(t *testing.T) {
	t.Cleanup(captcha.Provider.Reset)
	captcha.Provider.Override(func(*config.MeilingConfig) (captcha.Verifier, error) {
		return fakeVerifier{}, nil
	})
	env := newFeatureEnv(t)

	resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/instance", nil, nil)
	var info struct {
		Captcha *captcha.Widget `json:"captcha"`
	}
	decodeJSONBody(t, resp, &info)
	if info.Captcha == nil || info.Captcha.Provider != "fake" || info.Captcha.SiteKey != "site" {
		t.Fatalf("/v2/instance captcha = %+v, want the provider's widget", info.Captcha)
	}

	cases := []struct {
		name        string
		body        map[string]any
		wantBlocked bool
	}{
		{"missing", map[string]any{"email": "user@example.com"}, true},
		{"rejected", map[string]any{"email": "user@example.com", "captchaToken": "wrong"}, true},
		{"accepted", map[string]any{"email": "user@example.com", "captchaToken": "pass"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/verify", tc.body, nil)
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			blocked := strings.Contains(string(raw), "captcha_failed")
			if blocked != tc.wantBlocked {
				t.Fatalf("POST /v2/auth/verify = %d %s, want blocked=%v", resp.StatusCode, raw, tc.wantBlocked)
			}
			if blocked && resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("blocked status = %d, want 400", resp.StatusCode)
			}
		})
	}
}
