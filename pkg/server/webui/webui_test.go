//go:build !nowebui

// These tests serve the stock build, which a nowebui binary does not have.

package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

var hashedJSPath = regexp.MustCompile(`src="(/[^"]+/assets/[^"]+\.js)"`)
var hashedCSSPath = regexp.MustCompile(`href="(/[^"]+/assets/[^"]+\.css)"`)
var rootHashedJSPath = regexp.MustCompile(`src="(/assets/[^"]+\.js)"`)

func newTestConfig() *config.MeilingConfig {
	cfg := &config.MeilingConfig{}
	cfg.InstanceConfig.Name = "Test Instance"
	cfg.WebUIConfig.Enable = true
	cfg.WebUIConfig.BasePath = "/ui"
	_ = cfg.WebUIConfig.PostProcess()
	return cfg
}

func do(t *testing.T, app *fiber.App, path string) *http.Response {
	t.Helper()
	res, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil))
	if err != nil {
		t.Fatalf("request %s: %v", path, err)
	}
	return res
}

// TestDisabledByDefaultServesNothing proves the UI is opt-in: without
// webui.enable the routes are never registered, so an operator cannot end up
// exposing an interface they did not ask for.
func TestDisabledByDefaultServesNothing(t *testing.T) {
	app := fiber.New()
	cfg := &config.MeilingConfig{}

	if err := Register(app, cfg, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if res := do(t, app, "/ui/"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /ui/ status = %d, want 404 when disabled", res.StatusCode)
	}
}

// TestServesIndexAtMountPath proves the embedded assets are actually reachable,
// which also proves the go:embed directive captured them.
func TestServesIndexAtMountPath(t *testing.T) {
	app := fiber.New()
	if err := Register(app, newTestConfig(), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	res := do(t, app, "/ui/")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /ui/ status = %d, want 200", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	html := string(body)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Fatalf("GET /ui/ did not return the UI shell, got: %.120s", body)
	}
	if !strings.Contains(html, "/ui/assets/") {
		t.Fatalf("GET /ui/ shell is missing Vite hashed assets, got: %.240s", body)
	}
}

func firstSubmatch(t *testing.T, re *regexp.Regexp, html, what string) string {
	t.Helper()
	m := re.FindStringSubmatch(html)
	if len(m) < 2 {
		t.Fatalf("shell missing %s, got: %.240s", what, html)
	}
	return m[1]
}

func servedShell(t *testing.T, app *fiber.App, path string) string {
	t.Helper()
	res := do(t, app, path)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", path, res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	return string(body)
}

// TestServesStaticAssets proves the hashed Vite bundle the shell imports is
// embedded too; a missing file would leave a blank page at runtime.
func TestServesStaticAssets(t *testing.T) {
	app := fiber.New()
	if err := Register(app, newTestConfig(), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	html := servedShell(t, app, "/ui/")
	js := firstSubmatch(t, hashedJSPath, html, "hashed JS")
	css := firstSubmatch(t, hashedCSSPath, html, "hashed CSS")

	for _, asset := range []string{js, css, "/ui/favicon.svg"} {
		if res := do(t, app, asset); res.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", asset, res.StatusCode)
		}
	}
}

// TestEmbeddedAssetsAreCacheable proves the default production mode still sends
// long-lived caching headers, so the debugging convenience below does not cost
// every deployment a cache.
func TestEmbeddedAssetsAreCacheable(t *testing.T) {
	app := fiber.New()
	if err := Register(app, newTestConfig(), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	html := servedShell(t, app, "/ui/")
	js := firstSubmatch(t, hashedJSPath, html, "hashed JS")
	res := do(t, app, js)
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=3600") {
		t.Errorf("Cache-Control = %q, want a max-age for embedded assets", cc)
	}
}

// TestDirectoryModeDisablesCaching proves that serving from webui.path sends
// no-store. Without this, an edited file keeps being masked by the browser's
// copy and the developer debugs stale code.
func TestDirectoryModeDisablesCaching(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/index.html", []byte("<!DOCTYPE html><p>dev</p>"), 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}

	cfg := newTestConfig()
	cfg.WebUIConfig.Path = dir

	app := fiber.New()
	if err := Register(app, cfg, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	res := do(t, app, "/ui/")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /ui/ status = %d, want 200", res.StatusCode)
	}

	cc := res.Header.Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store in directory mode", cc)
	}

	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "dev") {
		t.Errorf("served embedded assets instead of the directory, got: %.80s", body)
	}
}

// TestDebugModeDisablesCaching proves debug.enabled also opts out of caching, so
// embedded-asset debugging does not need a separate directory.
func TestDebugModeDisablesCaching(t *testing.T) {
	cfg := newTestConfig()
	cfg.DebugConfig.Enabled = true

	app := fiber.New()
	if err := Register(app, cfg, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	html := servedShell(t, app, "/ui/")
	js := firstSubmatch(t, hashedJSPath, html, "hashed JS")
	res := do(t, app, js)
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store when debug.enabled is set", cc)
	}
}

// TestUnknownUIPathFallsBackToIndex proves client-side routes deep-link
// correctly instead of 404ing.
func TestUnknownUIPathFallsBackToIndex(t *testing.T) {
	app := fiber.New()
	if err := Register(app, newTestConfig(), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	res := do(t, app, "/ui/account/settings")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /ui/account/settings status = %d, want 200", res.StatusCode)
	}
}

// TestNestedRouteRewritesAssetURLs proves path-based client routes still load
// JS and CSS from the mount, not from the current URL directory.
func TestNestedRouteRewritesAssetURLs(t *testing.T) {
	app := fiber.New()
	if err := Register(app, newTestConfig(), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	res := do(t, app, "/ui/auth/signin")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /ui/auth/signin status = %d, want 200", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	html := string(body)
	js := firstSubmatch(t, hashedJSPath, html, "mount-absolute hashed JS")
	if !strings.HasPrefix(js, "/ui/assets/") {
		t.Errorf("hashed JS = %q, want a /ui/assets/ URL", js)
	}
	if strings.Contains(html, `src="assets/`) || strings.Contains(html, `src="./assets/`) {
		t.Error("shell still uses a relative asset URL, which would 404 on nested routes")
	}
}

// TestRootMountRewritesViteBase proves a "/" mount rewrites Vite's relative
// URLs so hashed files load from /assets/ rather than a leftover /ui/ prefix.
func TestRootMountRewritesViteBase(t *testing.T) {
	cfg := newTestConfig()
	cfg.WebUIConfig.BasePath = "/"
	if err := cfg.WebUIConfig.PostProcess(); err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	app := fiber.New()
	if err := Register(app, cfg, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	html := servedShell(t, app, "/")
	if strings.Contains(html, `"/ui/`) {
		t.Errorf("root-mount shell still references /ui/, got: %.240s", html)
	}
	js := firstSubmatch(t, rootHashedJSPath, html, "root-absolute hashed JS")
	if res := do(t, app, js); res.StatusCode != http.StatusOK {
		t.Errorf("GET %s status = %d, want 200", js, res.StatusCode)
	}
}

// TestRootMountPreservesAPIResponses proves that mounting the UI at "/" does
// not turn unmatched API requests into HTML. The static handler falls back to
// index.html for client-side routing, which at the root would otherwise hand a
// JSON client an HTML page and mask real 404s.
func TestRootMountPreservesAPIResponses(t *testing.T) {
	cfg := newTestConfig()
	cfg.WebUIConfig.BasePath = "/"
	if err := cfg.WebUIConfig.PostProcess(); err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	app := fiber.New()
	if err := Register(app, cfg, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// The UI answers at the root.
	if res := do(t, app, "/"); res.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", res.StatusCode)
	}

	// An unregistered API path must still 404 rather than returning the shell.
	// /v1 is reserved for an API mounted by an extension.
	for _, path := range []string{"/v2/users/", "/v1/signin"} {
		res := do(t, app, path)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, res.StatusCode)
		}
		body, _ := io.ReadAll(res.Body)
		if strings.Contains(string(body), "<!DOCTYPE html>") {
			t.Errorf("GET %s returned the HTML shell instead of an API response", path)
		}
	}
}

// TestOwnsRoot proves the helper the router relies on to avoid registering a
// competing "GET /" handler reports the mount accurately.
func TestOwnsRoot(t *testing.T) {
	nested := newTestConfig()
	if OwnsRoot(nested) {
		t.Error("OwnsRoot = true for a /ui mount, want false")
	}

	root := newTestConfig()
	root.WebUIConfig.BasePath = "/"
	_ = root.WebUIConfig.PostProcess()
	if !OwnsRoot(root) {
		t.Error("OwnsRoot = false for a root mount, want true")
	}

	disabled := newTestConfig()
	disabled.WebUIConfig.Enable = false
	disabled.WebUIConfig.BasePath = "/"
	_ = disabled.WebUIConfig.PostProcess()
	if OwnsRoot(disabled) {
		t.Error("OwnsRoot = true while disabled, want false")
	}
}

// TestBareMountRedirectsToTrailingSlash proves relative asset URLs resolve:
// without the redirect, /ui would resolve ./assets against "/" and 404.
func TestBareMountRedirectsToTrailingSlash(t *testing.T) {
	app := fiber.New()
	if err := Register(app, newTestConfig(), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	res := do(t, app, "/ui")
	if res.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("GET /ui status = %d, want 301", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/ui/" {
		t.Errorf("Location = %q, want %q", loc, "/ui/")
	}
}

// TestMissingDirectoryIsReported proves a bad webui.path surfaces as an error
// instead of silently serving an empty interface.
func TestMissingDirectoryIsReported(t *testing.T) {
	cfg := newTestConfig()
	cfg.WebUIConfig.Path = "/nonexistent/webui/assets"

	app := fiber.New()
	if err := Register(app, cfg, nil); err == nil {
		t.Fatal("Register returned nil error for a missing webui.path, want an error")
	}
}

// TestNestedMountLeavesAPIRoutesAlone proves mounting the UI cannot capture API
// traffic registered elsewhere.
func TestNestedMountLeavesAPIRoutesAlone(t *testing.T) {
	app := fiber.New()
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "OK"})
	})

	if err := Register(app, newTestConfig(), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	res := do(t, app, "/health")
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), `"status"`) {
		t.Fatalf("GET /health returned %.120s, want the JSON health payload", body)
	}
}

// TestAssetsOverrideIsServed proves a distribution can replace the embedded
// UI build through the Assets slot.
func TestAssetsOverrideIsServed(t *testing.T) {
	t.Cleanup(Assets.Reset)
	Assets.Override(fstest.MapFS{
		"index.html": {Data: []byte("<!DOCTYPE html><title>custom ui</title>")},
	})

	app := fiber.New()
	if err := Register(app, newTestConfig(), nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	res := do(t, app, "/ui/")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), "custom ui") {
		t.Fatalf("GET /ui/ = %d %.120s, want the overridden build", res.StatusCode, body)
	}
}

// TestDirectoryModeWinsOverAssetsOverride proves webui.path still takes
// precedence, so operators can swap the UI of any distribution at runtime.
func TestDirectoryModeWinsOverAssetsOverride(t *testing.T) {
	t.Cleanup(Assets.Reset)
	Assets.Override(fstest.MapFS{"index.html": {Data: []byte("override")}})

	dir := t.TempDir()
	if err := os.WriteFile(dir+"/index.html", []byte("<!DOCTYPE html>from disk"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg := newTestConfig()
	cfg.WebUIConfig.Path = dir

	app := fiber.New()
	if err := Register(app, cfg, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	body, _ := io.ReadAll(do(t, app, "/ui/").Body)
	if !strings.Contains(string(body), "from disk") {
		t.Fatalf("GET /ui/ = %.120s, want the webui.path build", body)
	}
}
