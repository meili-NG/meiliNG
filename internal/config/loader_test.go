package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	pkgconfig "github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestFindConfigPathSearchesParents(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, configFileName)
	if err := os.WriteFile(configPath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})

	if err := os.Chdir(nested); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	got, err := FindConfigPath()
	if err != nil {
		t.Fatalf("FindConfigPath: %v", err)
	}
	want, err := filepath.EvalSymlinks(configPath)
	if err != nil {
		t.Fatalf("EvalSymlinks(configPath): %v", err)
	}
	resolvedGot, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("EvalSymlinks(got): %v", err)
	}
	if resolvedGot != want {
		t.Fatalf("FindConfigPath = %q, want %q", resolvedGot, want)
	}
}

func TestLoadConfigFromPathWithDirectory(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, configFileName)
	if err := os.WriteFile(configPath, []byte(`{"instance":{"name":"from-file"},"server":{"publicUrl":"https://id.example.com"}}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfigFromPath(dir)
	if err != nil {
		t.Fatalf("LoadConfigFromPath: %v", err)
	}
	if cfg.InstanceConfig.Name != "from-file" {
		t.Fatalf("LoadConfigFromPath name = %q", cfg.InstanceConfig.Name)
	}
	if cfg.ServerConfig.PublicURL != "https://id.example.com" {
		t.Fatalf("LoadConfigFromPath address = %q", cfg.ServerConfig.PublicURL)
	}
}

func TestLoadConfigFromPathWithBackupCodeJSON(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, configFileName)
	if err := os.WriteFile(configPath, []byte(`{"server":{"publicUrl":"https://id.example.com"},"auth":{"backupCode":{"count":12,"maxCount":16,"codeBytes":6}}}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfigFromPath(dir)
	if err != nil {
		t.Fatalf("LoadConfigFromPath: %v", err)
	}
	if cfg.AuthConfig.BackupCode.Count != 12 {
		t.Fatalf("backup code count = %d, want 12", cfg.AuthConfig.BackupCode.Count)
	}
	if cfg.AuthConfig.BackupCode.MaxCount != 16 {
		t.Fatalf("backup code max count = %d, want 16", cfg.AuthConfig.BackupCode.MaxCount)
	}
	if cfg.AuthConfig.BackupCode.CodeBytes != 6 {
		t.Fatalf("backup code bytes = %d, want 6", cfg.AuthConfig.BackupCode.CodeBytes)
	}
}

// writeConfig writes a config file named name into a fresh directory and
// returns the directory.
func writeConfig(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir
}

func environ(vars map[string]string) func() []string {
	return func() []string {
		out := make([]string, 0, len(vars))
		for k, v := range vars {
			out = append(out, k+"="+v)
		}
		return out
	}
}

func mustLoad(t *testing.T, dir string, vars map[string]string) *pkgconfig.MeilingConfig {
	t.Helper()
	cfg, err := loadConfig(dir, environ(vars))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return cfg
}

func TestEnvOverridesFile(t *testing.T) {
	dir := writeConfig(t, "config.json", `{
		"instance": {"name": "from-file"},
		"server": {"publicUrl": "https://json.example.com", "listen": ":9090"}
	}`)

	cfg := mustLoad(t, dir, map[string]string{"MEILING_INSTANCE__NAME": "from-env"})

	if cfg.InstanceConfig.Name != "from-env" {
		t.Fatalf("env override did not apply: %q", cfg.InstanceConfig.Name)
	}
	if cfg.ServerConfig.PublicURL != "https://json.example.com" {
		t.Fatalf("defaults should not overwrite file values: %q", cfg.ServerConfig.PublicURL)
	}
	if cfg.ServerConfig.Listen != ":9090" {
		t.Fatalf("existing file values should be preserved: %q", cfg.ServerConfig.Listen)
	}
}

// TestFileFalseOverridesTrueDefault proves `false` in a config file turns off
// a setting that defaults to true.
func TestFileFalseOverridesTrueDefault(t *testing.T) {
	dir := writeConfig(t, "config.json", `{"oauth2": {"allowCreate": false}, "auth": {"signup": {"allowSignUp": false}}}`)

	cfg := mustLoad(t, dir, nil)

	if cfg.OAuth2Config.AllowCreate {
		t.Fatal("oauth2.allowCreate = true, want false from the config file")
	}
	if cfg.AuthConfig.SignUp.AllowSignUp {
		t.Fatal("auth.signup.allowSignUp = true, want false from the config file")
	}
}

func TestDefaultsApplyToEmptyConfig(t *testing.T) {
	cfg := mustLoad(t, writeConfig(t, "config.json", "{}"), nil)

	if !cfg.OAuth2Config.AllowCreate {
		t.Fatal("oauth2.allowCreate default should be true")
	}
	if cfg.OAuth2Config.ClientSecretLength != 64 {
		t.Fatalf("oauth2.clientSecretLength default = %d, want 64", cfg.OAuth2Config.ClientSecretLength)
	}
	if cfg.InstanceConfig.Name != "meiliNG" {
		t.Fatalf("instance.name default = %q", cfg.InstanceConfig.Name)
	}
	if cfg.ValkeyConfig.Timeout.String() != "5s" {
		t.Fatalf("valkey timeout = %s, want 5s", cfg.ValkeyConfig.Timeout)
	}
}

func TestEnvOverridesDefaults(t *testing.T) {
	dir := writeConfig(t, "config.json", "{}")

	cfg := mustLoad(t, dir, map[string]string{
		"MEILING_OAUTH2__CLIENT_SECRET_LENGTH":  "128",
		"MEILING_OAUTH2__ALLOW_CREATE":          "false",
		"MEILING_TOKEN__ACCESS_TOKEN__DURATION": "2h",
		"MEILING_NOT__A__KEY":                   "ignored",
	})

	if cfg.OAuth2Config.ClientSecretLength != 128 {
		t.Fatalf("clientSecretLength = %d, want 128 from MEILING_*", cfg.OAuth2Config.ClientSecretLength)
	}
	if cfg.OAuth2Config.AllowCreate {
		t.Fatal("allowCreate = true, want false from MEILING_OAUTH2__ALLOW_CREATE")
	}
	if cfg.TokenConfig.AccessToken.Duration.String() != "2h0m0s" {
		t.Fatalf("access token duration = %s, want 2h", cfg.TokenConfig.AccessToken.Duration)
	}
}

func TestEnvOverridesBackupCodesPerKey(t *testing.T) {
	dir := writeConfig(t, "config.json", `{"auth": {"backupCode": {"count": 12, "maxCount": 16, "codeBytes": 6}}}`)

	cfg := mustLoad(t, dir, map[string]string{"MEILING_AUTH__BACKUP_CODE__COUNT": "14"})

	if cfg.AuthConfig.BackupCode.Count != 14 {
		t.Fatalf("backup code count env override = %d, want 14", cfg.AuthConfig.BackupCode.Count)
	}
	if cfg.AuthConfig.BackupCode.MaxCount != 16 {
		t.Fatalf("backup code max count should preserve file value = %d, want 16", cfg.AuthConfig.BackupCode.MaxCount)
	}
	if cfg.AuthConfig.BackupCode.CodeBytes != 6 {
		t.Fatalf("backup code bytes should preserve file value = %d, want 6", cfg.AuthConfig.BackupCode.CodeBytes)
	}
}

func TestEnvListsAndMaps(t *testing.T) {
	dir := writeConfig(t, "config.json", "{}")

	cfg := mustLoad(t, dir, map[string]string{
		"MEILING_OAUTH2__CONSENT_FRONTENDS": "https://a.example.com, https://b.example.com",
		"MEILING_NOTIFICATION__KEYS":        "verification_code:vendor,reset:generic",
	})

	if got := cfg.OAuth2Config.ConsentFrontends; len(got) != 2 || got[0] != "https://a.example.com" || got[1] != "https://b.example.com" {
		t.Fatalf("consentFrontends = %#v", got)
	}
	if got := cfg.NotificationConfig.Keys; got["verification_code"] != "vendor" || got["reset"] != "generic" {
		t.Fatalf("notification keys = %#v", got)
	}
}

// TestEnvOverridesNotificationProviderSelection proves the provider selection
// variable reaches NotificationConfig, so setting it switches providers.
func TestEnvOverridesNotificationProviderSelection(t *testing.T) {
	cfg := mustLoad(t, writeConfig(t, "config.json", "{}"), map[string]string{
		"MEILING_NOTIFICATION__DEFAULT_PROVIDER": "vendor",
	})

	if cfg.NotificationConfig.DefaultProvider != "vendor" {
		t.Fatalf("notification.defaultProvider env override = %q, want %q", cfg.NotificationConfig.DefaultProvider, "vendor")
	}
}

// vendorSection stands in for a config section an optional component (such as
// a build-tagged notification provider) registers from init().
type vendorSection struct {
	BaseURL string   `json:"baseUrl" default:"https://vendor.example.com"`
	APIKey  string   `json:"apiKey"`
	Scopes  []string `json:"scopes"`
}

const vendorSectionPath = "notification.vendorTest"

var registerVendorSection sync.Once

func withVendorSection(t *testing.T) {
	t.Helper()
	registerVendorSection.Do(func() {
		pkgconfig.RegisterSection[vendorSection](vendorSectionPath)
	})
}

// TestRegisteredSectionLoadsLikeBuiltInConfig proves a registered section gets
// the same treatment as built-in settings: defaults, file keys and
// environment variables, all without a field on MeilingConfig.
func TestRegisteredSectionLoadsLikeBuiltInConfig(t *testing.T) {
	withVendorSection(t)

	dir := writeConfig(t, "config.yaml", "notification:\n  defaultProvider: vendor\n  vendor_test:\n    scopes: [a, b]\n")
	cfg := mustLoad(t, dir, map[string]string{
		"MEILING_NOTIFICATION__VENDOR_TEST__API_KEY":  "env-key",
		"MEILING_NOTIFICATION__VENDOR_TEST__BASE_URL": "https://override.example.com",
	})

	got, ok := pkgconfig.Section[vendorSection](cfg, vendorSectionPath)
	if !ok {
		t.Fatal("registered section was not loaded")
	}
	if got.APIKey != "env-key" {
		t.Fatalf("apiKey = %q, want the env value", got.APIKey)
	}
	if got.BaseURL != "https://override.example.com" {
		t.Fatalf("baseUrl = %q, want the env value", got.BaseURL)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("scopes = %#v, want the file value", got.Scopes)
	}
	// The section sits beside built-in keys without disturbing them.
	if cfg.NotificationConfig.DefaultProvider != "vendor" {
		t.Fatalf("defaultProvider = %q", cfg.NotificationConfig.DefaultProvider)
	}
}

func TestRegisteredSectionDefaultsAndSave(t *testing.T) {
	withVendorSection(t)

	cfg := mustLoad(t, writeConfig(t, "config.json", "{}"), nil)
	got, _ := pkgconfig.Section[vendorSection](cfg, vendorSectionPath)
	if got.BaseURL != "https://vendor.example.com" {
		t.Fatalf("baseUrl default = %q", got.BaseURL)
	}

	got.APIKey = "saved-key"
	cfg.SetSection(vendorSectionPath, got)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := SaveConfig(cfg, path); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	reloaded, _ := pkgconfig.Section[vendorSection](mustLoad(t, path, nil), vendorSectionPath)
	if reloaded.APIKey != "saved-key" {
		t.Fatalf("saved section apiKey = %q, want saved-key", reloaded.APIKey)
	}
}

func TestSectionCollidingWithBuiltInKeyIsRejected(t *testing.T) {
	_, err := buildSchema(reflect.TypeOf(pkgconfig.MeilingConfig{}), []pkgconfig.SectionType{
		{Path: "notification.keys", Type: reflect.TypeOf(vendorSection{})},
	})
	if err == nil {
		t.Fatal("expected an error for a section shadowing notification.keys")
	}

	_, err = buildSchema(reflect.TypeOf(pkgconfig.MeilingConfig{}), []pkgconfig.SectionType{
		{Path: "instance.name.vendor", Type: reflect.TypeOf(vendorSection{})},
	})
	if err == nil {
		t.Fatal("expected an error for a section nested under the instance.name setting")
	}
}

// TestFileKeysAreMatchedLoosely proves config keys match case-insensitively,
// ignoring _ and -.
func TestFileKeysAreMatchedLoosely(t *testing.T) {
	dir := writeConfig(t, "config.json", `{
		"Server": {"PublicURL": "https://id.example.com"},
		"oauth2": {"AllowCreate": false, "client_secret_length": 80},
		"notification": {"keys": {"Verification_Code": "vendor"}}
	}`)

	cfg := mustLoad(t, dir, nil)

	if cfg.ServerConfig.PublicURL != "https://id.example.com" {
		t.Fatalf("publicUrl = %q", cfg.ServerConfig.PublicURL)
	}
	if cfg.OAuth2Config.AllowCreate {
		t.Fatal("AllowCreate = true, want false")
	}
	if cfg.OAuth2Config.ClientSecretLength != 80 {
		t.Fatalf("clientSecretLength = %d, want 80", cfg.OAuth2Config.ClientSecretLength)
	}
	// Map keys are data, not config keys, so they keep their spelling.
	if cfg.NotificationConfig.Keys["Verification_Code"] != "vendor" {
		t.Fatalf("notification keys = %#v", cfg.NotificationConfig.Keys)
	}
}

func TestLoadYAMLAndTOML(t *testing.T) {
	cases := map[string]string{
		"config.yaml": "instance:\n  name: from-yaml\noauth2:\n  allowCreate: false\nserver:\n  proxyAddresses: [10.0.0.1, 10.0.0.2]\n",
		"config.toml": "[instance]\nname = \"from-toml\"\n[oauth2]\nallowCreate = false\n[server]\nproxyAddresses = [\"10.0.0.1\", \"10.0.0.2\"]\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := mustLoad(t, writeConfig(t, name, content), nil)

			if want := "from-" + strings.TrimPrefix(filepath.Ext(name), "."); cfg.InstanceConfig.Name != want {
				t.Fatalf("name = %q, want %q", cfg.InstanceConfig.Name, want)
			}
			if cfg.OAuth2Config.AllowCreate {
				t.Fatal("allowCreate = true, want false")
			}
			if len(cfg.ServerConfig.ProxyAddresses) != 2 {
				t.Fatalf("proxyAddresses = %#v", cfg.ServerConfig.ProxyAddresses)
			}
		})
	}
}

func TestSaveConfigRoundTrip(t *testing.T) {
	for _, name := range []string{"config.json", "config.yaml", "config.toml"} {
		t.Run(name, func(t *testing.T) {
			cfg := mustLoad(t, writeConfig(t, "config.json", `{"oauth2": {"allowCreate": false}, "instance": {"name": "saved"}}`), nil)

			path := filepath.Join(t.TempDir(), name)
			if err := SaveConfig(cfg, path); err != nil {
				t.Fatalf("SaveConfig: %v", err)
			}

			loaded := mustLoad(t, path, nil)
			if loaded.OAuth2Config.AllowCreate || loaded.InstanceConfig.Name != "saved" {
				t.Fatalf("round trip lost values: allowCreate=%v name=%q", loaded.OAuth2Config.AllowCreate, loaded.InstanceConfig.Name)
			}
		})
	}
}

// The local config file overrides the system one key by key, and the
// environment overrides both.
func TestLocalConfigOverridesTheSystemConfig(t *testing.T) {
	t.Cleanup(func() { pkgconfig.SetConfigDir("/etc/meiling") })
	pkgconfig.SetConfigDir(writeConfig(t, "config.yaml", "instance:\n  name: from-system\noauth2:\n  allowCreate: false\nserver:\n  listen: \":7000\"\n"))
	local := writeConfig(t, "config.json", `{"instance": {"name": "from-local"}}`)

	cfg := mustLoad(t, local, map[string]string{"MEILING_SERVER__LISTEN": ":9000"})
	if cfg.InstanceConfig.Name != "from-local" {
		t.Fatalf("instance.name = %q, want the local value", cfg.InstanceConfig.Name)
	}
	if cfg.OAuth2Config.AllowCreate {
		t.Fatal("oauth2.allowCreate = true, want false from the system file")
	}
	if cfg.ServerConfig.Listen != ":9000" {
		t.Fatalf("server.listen = %q, want the environment value", cfg.ServerConfig.Listen)
	}

	// With no local file the system file still applies.
	if cfg := mustLoad(t, "", nil); cfg.InstanceConfig.Name != "from-system" {
		t.Fatalf("instance.name without a local file = %q, want the system value", cfg.InstanceConfig.Name)
	}
}
