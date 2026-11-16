package notify

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// captureLog redirects the standard logger for the duration of fn and returns
// what was written.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()
	fn()
	return buf.String()
}

// TestLogResolutionReportsDefaultProvider proves the startup line names the
// generic provider when no configuration selects another one.
func TestLogResolutionReportsDefaultProvider(t *testing.T) {
	// The real generic provider lives in a package that would create an import
	// cycle here, so register a stub under the same name to exercise the
	// fallback path.
	if _, ok := Lookup(GenericProviderName); !ok {
		Register(stubProvider{name: GenericProviderName})
	}

	out := captureLog(func() {
		LogResolution(&config.MeilingConfig{})
	})

	if !strings.Contains(out, "notify: registered=") {
		t.Fatalf("missing registered list in log: %q", out)
	}
	if !strings.Contains(out, `default="generic"`) {
		t.Fatalf("expected default generic, got: %q", out)
	}
	if !strings.Contains(out, `verification_code->"generic"`) {
		t.Fatalf("expected verification_code to resolve to generic, got: %q", out)
	}
}

// TestLogResolutionReportsConfiguredDefault proves the startup line reflects a
// configured default provider in the resolution for each key.
func TestLogResolutionReportsConfiguredDefault(t *testing.T) {
	// Register a throwaway provider so selection can resolve to it.
	const name = "test-logresolution-provider"
	Register(stubProvider{name: name})

	cfg := &config.MeilingConfig{
		NotificationConfig: config.NotificationConfig{DefaultProvider: name},
	}

	out := captureLog(func() { LogResolution(cfg) })

	if !strings.Contains(out, `default="`+name+`"`) {
		t.Fatalf("expected configured default in log, got: %q", out)
	}
	if !strings.Contains(out, `verification_code->"`+name+`"`) {
		t.Fatalf("expected verification_code to resolve to %q, got: %q", name, out)
	}
}

// stubProvider is a minimal Provider that supports every key, used to verify
// resolution/logging without performing real delivery.
type stubProvider struct{ name string }

func (s stubProvider) Name() string            { return s.name }
func (s stubProvider) Supports(NotifyKey) bool { return true }
func (s stubProvider) Notify(context.Context, *config.MeilingConfig, Notification) error {
	return nil
}
