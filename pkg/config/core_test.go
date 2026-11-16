package config

import "testing"

func TestPopulateWithGlobalConfig(t *testing.T) {
	t.Parallel()

	cfg := MeilingConfig{
		InstanceConfig: InstanceConfig{Name: "Meiling"},
		ServerConfig:   ServerConfig{PublicURL: "https://api.example.com"},
		OAuth2Config:   OAuth2Config{ConsentFrontends: []string{"https://accounts.example.com/auth"}},
	}

	if err := cfg.PopulateDerivedDefaults(); err != nil {
		t.Fatalf("PopulateDerivedDefaults: %v", err)
	}

	if cfg.TokenConfig.JWT.Issuer != "https://api.example.com" {
		t.Fatalf("JwtConfig.Issuer = %q", cfg.TokenConfig.JWT.Issuer)
	}
	if cfg.AuthConfig.TOTP.Issuer != "Meiling" {
		t.Fatalf("TOTPConfig.Issuer = %q", cfg.AuthConfig.TOTP.Issuer)
	}
	if cfg.AuthConfig.WebAuthn.DisplayName != "Meiling" {
		t.Fatalf("WebAuthnConfig.DisplayName = %q", cfg.AuthConfig.WebAuthn.DisplayName)
	}
	if len(cfg.ServerConfig.FrontendOrigins) != 1 || cfg.ServerConfig.FrontendOrigins[0] != "https://accounts.example.com" {
		t.Fatalf("FrontendOrigins = %#v", cfg.ServerConfig.FrontendOrigins)
	}
	if len(cfg.AuthConfig.WebAuthn.RelyingPartyOrigins) != 1 || cfg.AuthConfig.WebAuthn.RelyingPartyOrigins[0] != "https://accounts.example.com" {
		t.Fatalf("RelyingPartyOrigins = %#v", cfg.AuthConfig.WebAuthn.RelyingPartyOrigins)
	}
	if cfg.AuthConfig.WebAuthn.RelyingPartyID != "accounts.example.com" {
		t.Fatalf("RelyingPartyID = %q", cfg.AuthConfig.WebAuthn.RelyingPartyID)
	}
}

func TestAllowsOrigin(t *testing.T) {
	t.Parallel()

	if (&ServerConfig{}).AllowsOrigin("https://ui.example.com") {
		t.Fatal("an empty server.frontendOrigins allowed an origin")
	}
	c := &ServerConfig{FrontendOrigins: []string{"https://UI.example.com", "http://localhost:5173"}}
	for origin, want := range map[string]bool{
		"https://ui.example.com":      true,
		"http://localhost:5173":       true,
		"http://ui.example.com":       false,
		"https://ui.example.com:8443": false,
		"http://localhost:5174":       false,
		"null":                        false,
		"":                            false,
	} {
		if got := c.AllowsOrigin(origin); got != want {
			t.Errorf("AllowsOrigin(%q) = %v, want %v", origin, got, want)
		}
	}
}
