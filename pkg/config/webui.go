package config

import "strings"

// WebUIConfig controls the optional built-in web interface. The UI is a
// static, client-side app that talks to this server's own /v2 API using a
// session bearer token, so enabling it adds no new privileged endpoints.
//
// It is disabled by default: an operator who already runs a separate frontend
// (see OAuth2Config.ConsentFrontends) should leave it off.
type WebUIConfig struct {
	// Enable serves the web interface when true.
	Enable bool `json:"enable,omitempty" default:"false"`

	// BasePath is the URL prefix the UI is mounted under. It is normalised to
	// a leading slash with no trailing slash, so "ui", "/ui" and "/ui/" are
	// equivalent. Use "/" to mount at the domain root.
	BasePath string `json:"basePath,omitempty" default:"/ui"`

	// Path optionally serves the UI from a directory on disk instead of the
	// assets embedded in the binary. Intended for local development and for
	// operators who want to ship a customised or entirely different frontend
	// without rebuilding Meiling.
	Path string `json:"path,omitempty"`

	// APIBaseURL is the origin the UI sends API requests to. Empty means
	// same-origin, which is the correct default when the UI is served by this
	// server. Set it only when the UI is served from a different host; the
	// server then does not auto-allow its own origin for frontend checks.
	APIBaseURL string `json:"apiBaseUrl,omitempty"`

	// AddressOverride is the public origin the UI is reached at, used when
	// building absolute links (e.g. the webui.provideAdminUrl sign-in link).
	// Empty falls back to server.publicUrl. Set it when the UI is served
	// behind a different public hostname than the API address.
	AddressOverride string `json:"addressOverride,omitempty"`

	// ProvideAdminURL generates a long-lived random admin token at startup and
	// logs a ready-to-use link into the admin panel. It only takes effect when
	// the web UI is enabled. Intended for bootstrapping an instance that has no
	// admin.adminTokens configured; the generated token lives only in memory and is
	// regenerated on every restart.
	ProvideAdminURL bool `json:"provideAdminUrl,omitempty" default:"false"`
}

// PostProcess normalises the mount path.
func (c *WebUIConfig) PostProcess() error {
	c.BasePath = NormalizeBasePath(c.BasePath)
	return nil
}

// NormalizeBasePath converts a user-supplied mount path into a canonical form:
// a single leading slash and no trailing slash. The root mount is returned as
// "/" since an empty prefix is not a usable Fiber path.
func NormalizeBasePath(path string) string {
	trimmed := strings.Trim(strings.TrimSpace(path), "/")
	if trimmed == "" {
		return "/"
	}
	return "/" + trimmed
}

// MountPath returns the path prefix the UI is served from.
func (c WebUIConfig) MountPath() string {
	return NormalizeBasePath(c.BasePath)
}

// PublicBaseURL returns the origin absolute UI links should use: the explicit
// webui.addressOverride when set, otherwise the provided fallback (normally
// server.publicUrl). The result has no trailing slash.
func (c WebUIConfig) PublicBaseURL(fallback string) string {
	base := strings.TrimSpace(c.AddressOverride)
	if base == "" {
		base = strings.TrimSpace(fallback)
	}
	return strings.TrimRight(base, "/")
}
