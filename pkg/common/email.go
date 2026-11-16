package common

import (
	"context"
	_ "embed"
	"net/mail"
	"strings"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/notify"
)

//go:embed disposable_emails.txt
var disposableEmails string

// SendVerificationCode dispatches a verification-code notification. The active
// provider for NotifyKeyVerificationCode decides how to render and deliver it
// (e.g. the built-in generic provider renders an HTML email, while a vendor
// provider might submit the code as a variable to a pre-registered template).
// lang may be an Accept-Language value; its first entry picks the language.
func SendVerificationCode(cfg *config.MeilingConfig, to string, code string, lang string) error {
	return sendCode(cfg, notify.NotifyKeyVerificationCode, to, code, lang)
}

// SendPhoneVerificationCode sends code to an E.164 phone number through the
// provider mapped to notify.NotifyKeyPhoneVerificationCode.
func SendPhoneVerificationCode(cfg *config.MeilingConfig, to string, code string, lang string) error {
	return sendCode(cfg, notify.NotifyKeyPhoneVerificationCode, to, code, lang)
}

func sendCode(cfg *config.MeilingConfig, key notify.NotifyKey, to string, code string, lang string) error {
	lang = normalizeLanguage(lang)
	return notify.Dispatch(context.Background(), cfg, notify.Notification{
		Key:       key,
		Recipient: to,
		Args: notify.Args{
			"code": code,
			"lang": lang,
		},
	})
}

// normalizeLanguage reduces an Accept-Language style value to the primary
// subtag of its first entry. Anything but letters gives "en", as the result
// selects a template file by name.
func normalizeLanguage(lang string) string {
	first, _, _ := strings.Cut(lang, ",")
	first, _, _ = strings.Cut(first, ";")
	first, _, _ = strings.Cut(strings.TrimSpace(first), "-")
	notLetter := func(r rune) bool { return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') }
	if first == "" || strings.ContainsFunc(first, notLetter) {
		return "en"
	}
	return first
}

func IsDisposableEmail(email string) bool {
	parsed, err := mail.ParseAddress(email)
	if err != nil {
		return true
	}

	blacklists := strings.Split(disposableEmails, "\n")
	for _, domain := range blacklists {
		// parse mail
		if strings.HasSuffix(parsed.Address, "@"+domain) {
			return true
		}
	}

	return false
}
