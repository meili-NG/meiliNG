package config

import "testing"

// TestNormalizeBasePath proves operator-supplied mount paths converge on one
// canonical form, so "/ui", "ui" and "/ui/" cannot produce three different
// mounts (and the root mount never becomes an empty, unroutable prefix).
func TestNormalizeBasePath(t *testing.T) {
	cases := map[string]string{
		"":            "/",
		"/":           "/",
		"ui":          "/ui",
		"/ui":         "/ui",
		"/ui/":        "/ui",
		"  /ui/  ":    "/ui",
		"account/ui":  "/account/ui",
		"/account/ui": "/account/ui",
	}

	for input, want := range cases {
		if got := NormalizeBasePath(input); got != want {
			t.Errorf("NormalizeBasePath(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestWebUIPostProcessNormalizes proves the mount path is canonicalised as part
// of the normal config pipeline, not only when callers remember to ask.
func TestWebUIPostProcessNormalizes(t *testing.T) {
	cfg := &MeilingConfig{}
	cfg.WebUIConfig.BasePath = "ui/"

	if err := cfg.WebUIConfig.PostProcess(); err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	if cfg.WebUIConfig.BasePath != "/ui" {
		t.Fatalf("BasePath = %q, want %q", cfg.WebUIConfig.BasePath, "/ui")
	}
}

// TestWebUIEnabledAllowsOwnOrigin proves enabling the built-in UI adds the
// server's own origin to the frontend allow-list. Without this the UI would be
// served successfully but every API call it made would be rejected by the
// frontend-origin check.
func TestWebUIEnabledAllowsOwnOrigin(t *testing.T) {
	cfg := &MeilingConfig{}
	cfg.ServerConfig.PublicURL = "https://id.example.com"
	cfg.OAuth2Config.ConsentFrontends = []string{"https://accounts.example.com/auth"}
	cfg.WebUIConfig.Enable = true

	if err := cfg.PopulateDerivedDefaults(); err != nil {
		t.Fatalf("PopulateDerivedDefaults: %v", err)
	}

	var found bool
	for _, origin := range cfg.ServerConfig.FrontendOrigins {
		if origin == "https://id.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FrontendOrigins = %v, want it to contain the server's own origin", cfg.ServerConfig.FrontendOrigins)
	}
}

// TestWebUIDisabledDoesNotChangeOrigins proves the origin allow-list is
// untouched when the UI is off, so enabling this feature is the only thing that
// can widen it.
func TestWebUIDisabledDoesNotChangeOrigins(t *testing.T) {
	cfg := &MeilingConfig{}
	cfg.ServerConfig.PublicURL = "https://id.example.com"
	cfg.OAuth2Config.ConsentFrontends = []string{"https://accounts.example.com/auth"}

	if err := cfg.PopulateDerivedDefaults(); err != nil {
		t.Fatalf("PopulateDerivedDefaults: %v", err)
	}

	want := []string{"https://accounts.example.com"}
	if len(cfg.ServerConfig.FrontendOrigins) != len(want) || cfg.ServerConfig.FrontendOrigins[0] != want[0] {
		t.Fatalf("FrontendOrigins = %v, want %v", cfg.ServerConfig.FrontendOrigins, want)
	}
}
