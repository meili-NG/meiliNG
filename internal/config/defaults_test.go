package config

import (
	"strings"
	"testing"
	"time"

	pkgconfig "github.com/meili-NG/meiliNG/v2/pkg/config"
)

func withDistributionDefaults(t *testing.T, defaults map[string]any) {
	t.Helper()
	pkgconfig.ResetDefaults()
	t.Cleanup(pkgconfig.ResetDefaults)
	for path, value := range defaults {
		pkgconfig.SetDefault(path, value)
	}
}

// TestDistributionDefaultsReplaceBuiltIns proves a distribution default wins
// over the `default` tag, with string values parsed like environment variables
// and paths matched as loosely as file keys.
func TestDistributionDefaultsReplaceBuiltIns(t *testing.T) {
	withDistributionDefaults(t, map[string]any{
		"instance.name":              "Acme ID",
		"server.public_url":          "https://id.acme.example",
		"auth.signup.allowSignUp":    "false",
		"server.frontendOrigins":     "https://a.example,https://b.example",
		"token.accessToken.duration": "45m",
		"auth.backupCode.count":      12,
	})

	cfg := mustLoad(t, writeConfig(t, "config.json", "{}"), nil)

	if cfg.InstanceConfig.Name != "Acme ID" || cfg.ServerConfig.PublicURL != "https://id.acme.example" {
		t.Fatalf("instance = %+v, server = %+v", cfg.InstanceConfig, cfg.ServerConfig)
	}
	if cfg.AuthConfig.SignUp.AllowSignUp {
		t.Fatal("auth.signup.allowSignUp default not replaced")
	}
	if len(cfg.ServerConfig.FrontendOrigins) != 2 {
		t.Fatalf("frontendOrigins = %#v", cfg.ServerConfig.FrontendOrigins)
	}
	if cfg.TokenConfig.AccessToken.Duration != 45*time.Minute {
		t.Fatalf("accessToken.duration = %v", cfg.TokenConfig.AccessToken.Duration)
	}
	if cfg.AuthConfig.BackupCode.Count != 12 {
		t.Fatalf("auth.backupCode.count = %d", cfg.AuthConfig.BackupCode.Count)
	}
	// Derived values follow the distribution default.
	if cfg.TokenConfig.JWT.Issuer != "https://id.acme.example" {
		t.Fatalf("token.jwt.issuer = %q, want it derived from the default address", cfg.TokenConfig.JWT.Issuer)
	}
}

// TestFileAndEnvOverrideDistributionDefaults proves operators keep the last
// word: config files and environment variables beat a distribution default.
func TestFileAndEnvOverrideDistributionDefaults(t *testing.T) {
	withDistributionDefaults(t, map[string]any{
		"instance.name":            "Acme ID",
		"debug.enabled":            true,
		"oauth2.allowCreate":       true,
		"auth.signup.maxUsernames": 5,
	})

	dir := writeConfig(t, "config.json", `{"instance": {"name": "From File"}}`)
	cfg := mustLoad(t, dir, map[string]string{
		"MEILING_DEBUG__ENABLED":       "false",
		"MEILING_OAUTH2__ALLOW_CREATE": "false",
	})

	if cfg.InstanceConfig.Name != "From File" {
		t.Fatalf("name = %q, want the file value", cfg.InstanceConfig.Name)
	}
	if cfg.DebugConfig.Enabled {
		t.Fatal("debug.enabled env did not override the distribution default")
	}
	if cfg.OAuth2Config.AllowCreate {
		t.Fatal("oauth2.allowCreate env did not override the distribution default")
	}
	if cfg.AuthConfig.SignUp.MaxUsernames != 5 {
		t.Fatalf("maxUsernames = %d, want the untouched distribution default", cfg.AuthConfig.SignUp.MaxUsernames)
	}
}

func TestDistributionDefaultForRegisteredSection(t *testing.T) {
	withVendorSection(t)
	withDistributionDefaults(t, map[string]any{
		vendorSectionPath + ".baseUrl": "https://dist.example",
	})

	cfg := mustLoad(t, writeConfig(t, "config.json", "{}"), nil)
	got, _ := pkgconfig.Section[vendorSection](cfg, vendorSectionPath)
	if got.BaseURL != "https://dist.example" {
		t.Fatalf("section baseUrl = %q, want the distribution default", got.BaseURL)
	}
}

func TestUnknownDistributionDefaultFailsLoading(t *testing.T) {
	withDistributionDefaults(t, map[string]any{"instance.nmae": "typo"})

	_, err := loadConfig(writeConfig(t, "config.json", "{}"), environ(nil))
	if err == nil || !strings.Contains(err.Error(), "instance.nmae") {
		t.Fatalf("err = %v, want it to name the unknown key", err)
	}
}
