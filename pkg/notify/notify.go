// Package notify provides a vendor-extensible abstraction for delivering
// outbound notifications (verification codes, alerts, ...) without assuming how
// they are rendered or transported.
//
// The core does NOT render message content. A notification is identified by a
// NotifyKey plus a set of arguments; each Provider is responsible for turning
// that key+args into an actual delivery. This supports both:
//
//   - providers that render content themselves (e.g. an SMTP provider that
//     fills in an HTML email template), and
//   - providers that only submit variables to an upstream that owns the
//     template (e.g. a messaging service where templates are pre-registered
//     with the carrier and only variables are sent).
//
// Providers register themselves via Register (typically from an init function)
// and are activated by blank-importing the provider package at the composition
// root, mirroring the database/sql driver model. Vendors can therefore supply
// delivery logic as a Go module without modifying core dispatch code.
package notify

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// NotifyKey identifies the intent of a notification (which message to send).
// Providers implement behaviour per key: an email provider renders a template
// for the key, while a template-registered provider maps the key to a
// pre-registered upstream template id.
type NotifyKey string

const (
	// NotifyKeyVerificationCode delivers a numeric verification code.
	// Expected args: "code" (string), "lang" (string, optional).
	NotifyKeyVerificationCode NotifyKey = "verification_code"

	// NotifyKeyPhoneVerificationCode delivers a numeric verification code to
	// an E.164 phone number. Expected args: "code" (string), "lang" (string).
	// No built-in provider supports it: phone verification stays unavailable
	// until a provider for this key is registered and mapped in
	// notification.keys.
	NotifyKeyPhoneVerificationCode NotifyKey = "phone_verification_code"
)

// KnownKeys lists every notification key the core dispatches. It exists so
// startup diagnostics can report how each key resolves without hard-coding the
// list at the call site.
func KnownKeys() []NotifyKey {
	return []NotifyKey{
		NotifyKeyVerificationCode,
		NotifyKeyPhoneVerificationCode,
	}
}

// Args carries the variables for a notification. Values are provider-defined
// per NotifyKey; helper accessors below avoid repetitive type assertions.
type Args map[string]any

// String returns the value for key as a string, or "" if absent or not a string.
func (a Args) String(key string) string {
	if a == nil {
		return ""
	}
	if v, ok := a[key].(string); ok {
		return v
	}
	return ""
}

// Notification is a channel-agnostic delivery request. It deliberately carries
// no rendered subject/body: rendering is the provider's responsibility.
type Notification struct {
	// Key selects what to send. Providers branch on this.
	Key NotifyKey
	// Recipient is the destination, interpreted by the provider
	// (an email address, an E.164 phone number, a channel id, ...).
	Recipient string
	// Args holds the variables the provider needs to render or submit.
	Args Args
}

// Provider delivers notifications for one or more NotifyKeys.
//
// Implementations must be safe for concurrent use. A provider is selected per
// key via configuration (see config.NotificationConfig).
type Provider interface {
	// Name is the stable identifier used to select this provider in config.
	Name() string
	// Supports reports whether this provider can deliver the given key.
	Supports(key NotifyKey) bool
	// Notify delivers a single notification. cfg is the active Meiling
	// configuration so providers can read their own config sections.
	Notify(ctx context.Context, cfg *config.MeilingConfig, n Notification) error
}
