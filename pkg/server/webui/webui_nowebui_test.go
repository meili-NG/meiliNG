//go:build nowebui

package webui

import (
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// TestRegisterFailsWithoutUIBuild proves a nowebui binary refuses to enable
// the web UI when nothing replaces the stock build.
func TestRegisterFailsWithoutUIBuild(t *testing.T) {
	cfg := &config.MeilingConfig{}
	cfg.WebUIConfig.Enable = true
	if err := Register(fiber.New(), cfg, nil); err == nil {
		t.Fatal("expected an error: no UI build is embedded")
	}
}
