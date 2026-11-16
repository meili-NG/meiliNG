package common

import (
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestIsDisposableEmail(t *testing.T) {
	t.Parallel()

	domains := strings.Split(strings.TrimSpace(disposableEmails), "\n")
	if len(domains) == 0 || domains[0] == "" {
		t.Fatalf("expected embedded disposable email list to be populated")
	}

	if !IsDisposableEmail("user@" + domains[0]) {
		t.Fatalf("expected %q to be treated as disposable", domains[0])
	}
	if !IsDisposableEmail("not-an-email") {
		t.Fatalf("expected invalid email addresses to be rejected")
	}
	if IsDisposableEmail("user@example.com") {
		t.Fatalf("expected normal email to not be treated as disposable")
	}
}

func TestGeneralizePhone(t *testing.T) {
	t.Parallel()

	got, err := GeneralizePhone(&config.MeilingConfig{
		AuthConfig: config.AuthConfig{Phone: config.PhoneConfig{FallbackCountry: "US"}},
	}, "(415) 555-0132")
	if err != nil {
		t.Fatalf("GeneralizePhone: %v", err)
	}
	if got != "+14155550132" {
		t.Fatalf("GeneralizePhone = %q", got)
	}
}

func TestNormalizeLanguage(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]string{
		"":                        "en",
		"*":                       "en",
		"ko":                      "ko",
		"ko-KR":                   "ko",
		"ko-KR,ko;q=0.9":          "ko",
		"ko;q=0.9, en;q=0.8":      "ko",
		" fr-CA , en":             "fr",
		"../../secret":            "en",
		"ko/../../secret,en":      "en",
		"en\u0000":                "en",
		"*;q=0.5":                 "en",
		"zh-Hant-TW,zh;q=0.9":     "zh",
		"de_DE":                   "en",
		"en-US,en;q=0.9,ko;q=0.8": "en",
	} {
		if got := normalizeLanguage(input); got != want {
			t.Errorf("normalizeLanguage(%q) = %q, want %q", input, got, want)
		}
	}
}
