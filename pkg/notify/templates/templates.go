// Package templates holds the message templates that rendering notification
// providers (such as the built-in SMTP "generic" provider) use, one override
// slot per notification key.
//
// Core ships neutral defaults that take the instance name from instance.name and
// the logo and support link from the branding config section. Operators can
// replace them with files, without rebuilding (see files.go and
// notification.templatesPath). A distribution replaces a template from init(),
// typically with its own templ component:
//
//	func init() {
//		templates.VerificationCode.Override(func(d templates.VerificationCodeData) templates.Message {
//			return templates.Message{Subject: "...", Body: mytempl.VerificationCode(d)}
//		})
//	}
//
// Each key gets a data struct rather than positional arguments, so core can
// add fields without breaking existing overrides.
//
// Providers that only submit variables to an upstream that owns the template
// do not use this package.
package templates

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/a-h/templ"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
)

// Template renders the message for one notification key from its data.
type Template[D any] func(D) Message

// Message is a rendered notification: a subject line and an HTML body.
type Message struct {
	Subject string
	Body    templ.Component
}

// Branding is the instance identity shared by every template.
type Branding struct {
	// Name is the instance display name (instance.name).
	Name string
	// LogoURL is an absolute logo image URL, or empty for no logo.
	LogoURL string
	// SupportURL is a help page URL, or empty for no help section.
	SupportURL string
}

// BrandingFrom builds the Branding for cfg.
func BrandingFrom(cfg *config.MeilingConfig) Branding {
	if cfg == nil {
		return Branding{}
	}
	return Branding{
		Name:       cfg.InstanceConfig.Name,
		LogoURL:    cfg.InstanceConfig.LogoURL,
		SupportURL: cfg.InstanceConfig.SupportURL,
	}
}

// VerificationCodeData is the input of the verification_code template.
type VerificationCodeData struct {
	Code string
	// Lang is the requested language, e.g. "en" or "ko". Defaults to "en".
	Lang     string
	Branding Branding
}

// VerificationCode renders the verification_code notification.
var VerificationCode = ext.NewSlot[Template[VerificationCodeData]](defaultVerificationCode)

// RenderVerificationCode renders verification_code for cfg: from the
// operator's template files when present, otherwise with the active
// VerificationCode template.
func RenderVerificationCode(cfg *config.MeilingConfig, d VerificationCodeData) (Message, error) {
	active := VerificationCode.Get()
	msg, ok, err := fromFiles(cfg, "verification_code", d.Lang, d, func() string { return active(d).Subject })
	if err != nil || ok {
		return msg, err
	}
	return active(d), nil
}

// verificationCodeText is the wording of the default verification_code e-mail
// in one language.
type verificationCodeText struct {
	lang, subject, intro, expiry, ignore, help string
}

var verificationCodeTexts = map[string]verificationCodeText{
	"en": {
		lang:    "en",
		subject: "verification code",
		intro:   "Enter this code to confirm your e-mail address.",
		expiry:  "This code expires shortly.",
		ignore:  "If you did not request this code, you can ignore this e-mail.",
		help:    "Get help",
	},
	"ko": {
		lang:    "ko",
		subject: "인증 코드",
		intro:   "이메일 주소를 확인하려면 다음 코드를 입력하세요.",
		expiry:  "이 코드는 곧 만료됩니다.",
		ignore:  "코드를 요청하지 않으셨다면 이 메일을 무시하셔도 됩니다.",
		help:    "도움말",
	},
}

func verificationCodeTextFor(lang string) verificationCodeText {
	if text, ok := verificationCodeTexts[lang]; ok {
		return text
	}
	return verificationCodeTexts["en"]
}

func defaultVerificationCode(d VerificationCodeData) Message {
	subject := strings.TrimSpace(d.Branding.Name + " " + verificationCodeTextFor(d.Lang).subject)
	return Message{Subject: subject, Body: verificationCodeBody(d)}
}

// RenderString renders m.Body to a string.
func (m Message) RenderString(ctx context.Context) (string, error) {
	if m.Body == nil {
		return "", errors.New("templates: message has no body")
	}
	var buf bytes.Buffer
	if err := m.Body.Render(ctx, &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}
