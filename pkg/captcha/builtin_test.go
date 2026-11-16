package captcha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	internalconfig "github.com/meili-NG/meiliNG/v2/internal/config"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestBuiltinSelectsTheEnabledProvider(t *testing.T) {
	cfg := &config.MeilingConfig{}
	if v, err := Builtin(cfg); err != nil || v != nil {
		t.Fatalf("Builtin unconfigured = %v, %v; want off", v, err)
	}

	cfg.SetSection(TurnstileSection, TurnstileConfig{Enabled: true})
	if _, err := Builtin(cfg); err == nil {
		t.Fatal("turnstile enabled without a secret succeeded, want an error")
	}

	cfg.SetSection(TurnstileSection, TurnstileConfig{Enabled: true, Secret: "s", SiteKey: "tk"})
	if v, err := Builtin(cfg); err != nil || v == nil || v.Widget() != (Widget{Provider: "turnstile", SiteKey: "tk"}) {
		t.Fatalf("Builtin with turnstile = %v, %v", v, err)
	}

	cfg.SetSection(RecaptchaSection, RecaptchaConfig{Enabled: true, Secret: "s"})
	if _, err := Builtin(cfg); err == nil {
		t.Fatal("both providers enabled succeeded, want an error")
	}

	cfg.SetSection(TurnstileSection, TurnstileConfig{})
	cfg.SetSection(RecaptchaSection, RecaptchaConfig{Enabled: true, Secret: "s", SiteKey: "rk"})
	if v, err := Builtin(cfg); err != nil || v == nil || v.Widget() != (Widget{Provider: "recaptcha", SiteKey: "rk"}) {
		t.Fatalf("Builtin with recaptcha = %v, %v", v, err)
	}
}

func TestSiteverify(t *testing.T) {
	var answer string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("secret") != "sec" || r.FormValue("response") != "tok" || r.FormValue("remoteip") != "192.0.2.1" {
			t.Errorf("form = %v", r.Form)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()

	v := siteverify{provider: "recaptcha", url: srv.URL, secret: "sec", minScore: 0.5}
	for _, tc := range []struct {
		answer string
		want   bool
	}{
		{`{"success":true}`, true},
		{`{"success":false,"error-codes":["invalid-input-response"]}`, false},
		{`{"success":true,"score":0.9}`, true},
		{`{"success":true,"score":0.1}`, false},
	} {
		answer = tc.answer
		if ok, err := v.Verify(context.Background(), "tok", "192.0.2.1"); err != nil || ok != tc.want {
			t.Fatalf("Verify with %s = %v, %v; want %v", tc.answer, ok, err, tc.want)
		}
	}

	status = http.StatusInternalServerError
	if _, err := v.Verify(context.Background(), "tok", "192.0.2.1"); err == nil {
		t.Fatal("Verify on HTTP 500 succeeded, want an error")
	}
}

func TestBuiltinConfigLoads(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"captcha":{"recaptcha":{"enabled":true}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEILING_CAPTCHA__TURNSTILE__SECRET", "from-env")
	cfg, err := internalconfig.LoadConfigWithPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	turnstile, _ := config.Section[TurnstileConfig](cfg, TurnstileSection)
	recaptcha, _ := config.Section[RecaptchaConfig](cfg, RecaptchaSection)
	if turnstile.Secret != "from-env" || !recaptcha.Enabled || recaptcha.MinScore != 0.5 {
		t.Fatalf("turnstile = %+v, recaptcha = %+v", turnstile, recaptcha)
	}
}
