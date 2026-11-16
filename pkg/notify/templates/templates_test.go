package templates

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

func TestDefaultVerificationCodeUsesBranding(t *testing.T) {
	msg := VerificationCode.Get()(VerificationCodeData{
		Code: "123456",
		Lang: "en",
		Branding: Branding{
			Name:       "Acme ID",
			LogoURL:    "https://acme.example/logo.png",
			SupportURL: "https://acme.example/help",
		},
	})
	body, err := msg.RenderString(context.Background())
	if err != nil {
		t.Fatalf("RenderString: %v", err)
	}
	for _, want := range []string{"123456", "Acme ID", "https://acme.example/logo.png", "https://acme.example/help"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if msg.Subject == "" {
		t.Error("empty subject")
	}
}

func TestDefaultVerificationCodeOmitsUnsetBranding(t *testing.T) {
	msg := VerificationCode.Default()(VerificationCodeData{Code: "123456", Lang: "ko", Branding: Branding{Name: "Acme"}})
	body, err := msg.RenderString(context.Background())
	if err != nil {
		t.Fatalf("RenderString: %v", err)
	}
	if strings.Contains(body, "<img") || strings.Contains(body, "<a ") {
		t.Fatalf("unset logo/support URL still rendered: %s", body)
	}
	if !strings.Contains(body, "이 코드는 곧 만료됩니다.") || !strings.Contains(body, `lang="ko"`) {
		t.Fatal("ko body not rendered in Korean")
	}
	if msg.Subject != "Acme 인증 코드" {
		t.Fatalf("ko subject = %q", msg.Subject)
	}
}

func TestVerificationCodeOverride(t *testing.T) {
	t.Cleanup(VerificationCode.Reset)
	VerificationCode.Override(func(d VerificationCodeData) Message {
		return Message{Subject: "custom", Body: templ.Raw("code=" + d.Code)}
	})

	msg := VerificationCode.Get()(VerificationCodeData{Code: "42"})
	body, err := msg.RenderString(context.Background())
	if err != nil {
		t.Fatalf("RenderString: %v", err)
	}
	if msg.Subject != "custom" || body != "code=42" {
		t.Fatalf("override not applied: subject=%q body=%q", msg.Subject, body)
	}
}
