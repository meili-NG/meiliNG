package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	pkgconfig "github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestDistributionPresetsRelocateConfig(t *testing.T) {
	t.Cleanup(func() {
		pkgconfig.SetEnvPrefix("MEILING_")
		pkgconfig.SetConfigDir("/etc/meiling")
	})
	pkgconfig.SetEnvPrefix("ACME_")
	pkgconfig.SetConfigDir("/etc/acme")

	cfg := mustLoad(t, writeConfig(t, "config.json", "{}"), map[string]string{
		"ACME_INSTANCE__NAME":    "from-acme",
		"MEILING_SERVER__LISTEN": ":1",
	})
	if cfg.InstanceConfig.Name != "from-acme" {
		t.Fatalf("instance.name = %q, want the ACME_ value", cfg.InstanceConfig.Name)
	}
	if cfg.ServerConfig.Listen == ":1" {
		t.Fatal("the replaced MEILING_ prefix was still read")
	}

	dir := t.TempDir()
	pkgconfig.SetConfigDir(dir)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := SystemConfigPath(); runtime.GOOS != "windows" && got != filepath.Join(dir, "config.json") {
		t.Fatalf("SystemConfigPath = %q, want the file in the replaced config dir", got)
	}
}
