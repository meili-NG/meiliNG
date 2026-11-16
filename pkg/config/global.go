package config

import (
	"fmt"
	"slices"
)

// Kinds of admin credential admin.accept lists.
const (
	// AdminAcceptToken is a token listed in admin.adminTokens.
	AdminAcceptToken = "token"
	// AdminAcceptBootstrap is the web UI's bootstrap token (webui.provideAdminUrl).
	AdminAcceptBootstrap = "bootstrap"
	// AdminAcceptService is an OAuth2 access token a client got for
	// admin.adminTokenAudience, which only an admin can assign to it.
	AdminAcceptService = "service"
)

type AdminConfig struct {
	AdminTokenMethod   string   `json:"adminTokenMethod" default:"Meiling-Admin-Token"`
	AdminTokenAudience string   `json:"adminTokenAudience"`
	AdminTokens        []string `json:"adminTokens"`
	// Accept lists the kinds of credential treated as an admin: token,
	// bootstrap and service. Each still needs its own settings. An empty list
	// admits no admin.
	Accept []string `json:"accept" default:"token,bootstrap"`
}

// Accepts reports whether credentials of kind are admitted as an admin.
func (c AdminConfig) Accepts(kind string) bool {
	return slices.Contains(c.Accept, kind)
}

// Validate rejects unknown kinds in admin.accept.
func (c AdminConfig) Validate() error {
	for _, kind := range c.Accept {
		if kind != AdminAcceptToken && kind != AdminAcceptBootstrap && kind != AdminAcceptService {
			return fmt.Errorf("admin.accept: unknown credential kind %q (known: token, bootstrap, service)", kind)
		}
	}
	return nil
}

// NotificationConfig selects which registered notify provider handles each
// notification key. Providers are registered in-binary (see pkg/notify) and
// selected here by name, allowing vendor-supplied providers (e.g. a messaging
// provider that submits variables to a pre-registered template) to replace
// the built-in "generic" provider without code changes.
type NotificationConfig struct {
	// DefaultProvider is the provider name used for any key that has no
	// explicit mapping. Empty means the built-in "generic" provider.
	DefaultProvider string `json:"defaultProvider"`
	// Keys maps a notification key (e.g. "verification_code") to a provider
	// name. Mappings here take precedence over DefaultProvider.
	Keys map[string]string `json:"keys"`
	// TemplatesPath is a directory of operator email templates that replace
	// the built-in ones per key, without rebuilding. See pkg/notify/templates.
	TemplatesPath string `json:"templatesPath"`
	// SMTP is the mail server of the built-in "generic" provider.
	SMTP SMTPConfig `json:"smtp"`
}

// InstanceConfig is the identity of this instance, used in user-facing content
// such as notification emails, the web UI and the API docs. LogoURL and
// SupportURL are public: GET /v2/instance exposes them.
type InstanceConfig struct {
	Name string `json:"name" default:"meiliNG"`
	// LogoURL is an absolute URL to a logo image shown in emails and the web
	// UI. Empty omits the logo.
	LogoURL string `json:"logoUrl"`
	// SupportURL is where users are pointed for help. Empty omits the help
	// section.
	SupportURL string `json:"supportUrl"`
	// Description describes the service in the API root and API docs. Empty
	// uses a generic sentence built from Name.
	Description string `json:"description"`
	// AvatarFallbackURL is the picture URL template of users without an
	// uploaded avatar, used by avatar.Template. {email} expands to the
	// URL-escaped email, {email_md5} and {email_sha256} to hashes of it. Empty disables
	// the fallback.
	AvatarFallbackURL string `json:"avatarFallbackUrl" default:"https://www.gravatar.com/avatar/{email_md5}"`
}

// ServiceDescription returns instance.description, or a generic description
// of the instance when it is unset.
func (c *MeilingConfig) ServiceDescription() string {
	if c.InstanceConfig.Description != "" {
		return c.InstanceConfig.Description
	}
	return c.InstanceConfig.Name + " is a secure authentication and authorization service."
}

// DebugConfig controls diagnostics. Keep it off in production: it adds
// internal error details to API responses.
type DebugConfig struct {
	Enabled           bool `json:"enabled" default:"false"`
	PrintStackTrace   bool `json:"printStackTrace" default:"false"`
	RespondStackTrace bool `json:"respondStackTrace" default:"false"`
}

type SMTPConfig struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	From          string `json:"from"`
	UseTLS        bool   `json:"useTls" default:"false"`
	TLSServerName string `json:"tlsServerName"`
}
