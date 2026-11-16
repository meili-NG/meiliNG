package templates

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func templateDir(t *testing.T, files map[string]string) *config.MeilingConfig {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	cfg := &config.MeilingConfig{}
	cfg.NotificationConfig.TemplatesPath = dir
	return cfg
}

func render(t *testing.T, cfg *config.MeilingConfig, d VerificationCodeData) (string, string) {
	t.Helper()
	msg, err := RenderVerificationCode(cfg, d)
	if err != nil {
		t.Fatalf("RenderVerificationCode: %v", err)
	}
	body, err := msg.RenderString(context.Background())
	if err != nil {
		t.Fatalf("RenderString: %v", err)
	}
	return msg.Subject, body
}

func TestFileTemplatesOverrideByLanguage(t *testing.T) {
	cfg := templateDir(t, map[string]string{
		"verification_code.html":           "<p>{{.Branding.Name}}: {{.Code}}</p>",
		"verification_code.ko.html":        "<p>인증코드 {{.Code}}</p>",
		"verification_code.subject.txt":    "Your {{.Branding.Name}} code\n",
		"verification_code.ko.subject.txt": "{{.Branding.Name}} 인증번호",
	})
	data := VerificationCodeData{Code: "123456", Branding: Branding{Name: "Acme & Co"}}

	data.Lang = "en"
	subject, body := render(t, cfg, data)
	if subject != "Your Acme & Co code" {
		t.Fatalf("subject = %q, want the plain-text subject file", subject)
	}
	if body != "<p>Acme &amp; Co: 123456</p>" {
		t.Fatalf("body = %q, want the escaped generic body file", body)
	}

	data.Lang = "ko"
	subject, body = render(t, cfg, data)
	if subject != "Acme & Co 인증번호" || body != "<p>인증코드 123456</p>" {
		t.Fatalf("ko = %q / %q, want the ko files", subject, body)
	}
}

func TestFileTemplateWithoutSubjectKeepsActiveSubject(t *testing.T) {
	t.Cleanup(VerificationCode.Reset)
	VerificationCode.Override(func(d VerificationCodeData) Message {
		return Message{Subject: "distribution subject", Body: templ.Raw("distribution body")}
	})
	cfg := templateDir(t, map[string]string{"verification_code.html": "file body {{.Code}}"})

	subject, body := render(t, cfg, VerificationCodeData{Code: "1"})
	if subject != "distribution subject" || body != "file body 1" {
		t.Fatalf("got %q / %q, want the file body with the distribution subject", subject, body)
	}
}

func TestNoTemplateFileFallsBackToSlot(t *testing.T) {
	cfg := templateDir(t, map[string]string{"other_key.html": "unrelated"})

	_, body := render(t, cfg, VerificationCodeData{Code: "777", Branding: Branding{Name: "Acme"}})
	if !strings.Contains(body, "777") || strings.Contains(body, "unrelated") {
		t.Fatalf("body = %q, want the built-in template", body)
	}
}

func TestBrokenFileTemplateFails(t *testing.T) {
	cfg := templateDir(t, map[string]string{"verification_code.html": "{{.Missing"})

	if _, err := RenderVerificationCode(cfg, VerificationCodeData{Code: "1"}); err == nil {
		t.Fatal("broken template rendered without error")
	}
}
