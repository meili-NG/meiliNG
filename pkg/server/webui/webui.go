// Package webui serves the optional built-in web interface.
//
// The UI is a static client-side application: it is delivered as plain HTML,
// CSS and JavaScript, and every privileged operation goes through the existing
// /v2 API with a session bearer token. Serving it therefore adds no new
// authenticated endpoints and no new trust boundary — anything the UI can do,
// an operator could already do with curl and the same token.
//
// The production Vite build in ui/dist is embedded in the binary by default
// so a single binary is self-contained. A distribution can embed a different
// build by overriding Assets. Setting webui.path serves from a directory
// instead of either, which is useful for development and for replacing the UI
// without rebuilding. Rebuild the embed with: go generate ./ui
package webui

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"github.com/meili-NG/meiliNG/v2/ui"
)

// adminTokenLength is the size of the bootstrap admin token generated when
// webui.provideAdminUrl is enabled. Long enough to be infeasible to guess.
const adminTokenLength = 64

// Assets is the UI build served when webui.path is unset: a filesystem with
// index.html at its root. It defaults to the embedded ui/dist build. A
// distribution embeds its own build and overrides it from init():
//
//	//go:embed all:dist
//	var dist embed.FS
//
//	func init() {
//		sub, _ := fs.Sub(dist, "dist")
//		webui.Assets.Override(sub)
//	}
var Assets = ext.NewSlot[fs.FS](embeddedDist())

func embeddedDist() fs.FS {
	sub, err := fs.Sub(ui.Dist, "dist")
	if err != nil {
		// fs.Sub only fails on an invalid path, and "dist" is a constant.
		panic(err)
	}
	return sub
}

// assetsFS returns the filesystem the UI is served from, plus a label used in
// startup logs so operators can tell embedded and on-disk modes apart.
func assetsFS(cfg config.WebUIConfig) (http.FileSystem, string, error) {
	if cfg.Path != "" {
		if _, err := os.Stat(cfg.Path); err != nil {
			return nil, "", err
		}
		return http.Dir(cfg.Path), "directory " + cfg.Path, nil
	}

	source := "embedded assets"
	if Assets.Overridden() {
		source = "distribution assets"
	}
	// An empty build (-tags nowebui without an override, or ui/dist never
	// built) would otherwise start and answer every page with a 404.
	if _, err := fs.Stat(Assets.Get(), "index.html"); err != nil {
		return nil, "", fmt.Errorf("web UI is enabled but the binary has no UI build (%s): set webui.path, override webui.Assets, or build without -tags nowebui: %w", source, err)
	}
	return http.FS(Assets.Get()), source, nil
}

// Register mounts the web UI when it is enabled. It is a no-op otherwise, so
// callers do not need to check the flag themselves. The token services are
// used to coordinate the webui.provideAdminUrl magic token across a cluster
// (via the shared Valkey store); pass nil for single-process behavior.
func Register(app *fiber.App, cfg *config.MeilingConfig, services *tokens.Services) error {
	if cfg == nil || !cfg.WebUIConfig.Enable {
		return nil
	}

	assets, source, err := assetsFS(cfg.WebUIConfig)
	if err != nil {
		return err
	}

	mount := cfg.WebUIConfig.MountPath()

	// The bare prefix has to be redirected before the static handler runs,
	// because that handler also matches "/ui" and would serve the shell
	// directly. index.html references its assets relatively, so a page served
	// at "/ui" would resolve them against "/" and fail to load. Fiber treats
	// "/ui" and "/ui/" as the same route, so the exact path is compared here
	// rather than relying on route matching.
	if mount != "/" {
		app.Use(mount, func(c *fiber.Ctx) error {
			if c.Path() == mount {
				return c.Redirect(mount+"/", fiber.StatusMovedPermanently)
			}
			return c.Next()
		})
	}

	// Long-lived caching is right for embedded assets, which only change when
	// the binary does. It is wrong while editing files on disk or debugging,
	// where a stale bundle silently hides the change under test.
	maxAge := 3600
	if cfg.WebUIConfig.Path != "" || cfg.DebugConfig.Enabled {
		maxAge = 0
	}

	static := filesystem.New(filesystem.Config{
		Root:   assets,
		Index:  "index.html",
		MaxAge: maxAge,
	})

	if maxAge == 0 {
		// MaxAge 0 only omits Cache-Control; browsers still heuristically
		// cache, so revalidation is requested explicitly.
		app.Use(mount, func(c *fiber.Ctx) error {
			c.Set(fiber.HeaderCacheControl, "no-store, must-revalidate")
			return c.Next()
		})
	}

	// Client-side routes (auth/signin, users/:id/settings/...) are not files,
	// so they need the shell. Vite emits relative ./asset URLs; rewriteShell
	// makes them mount-absolute so nested routes do not 404 the bundle.
	serveShell := func(c *fiber.Ctx) error {
		return sendShell(c, assets, cfg.WebUIConfig, maxAge)
	}

	if mount == "/" {
		app.Use("/", func(c *fiber.Ctx) error {
			if isAPIPath(c.Path()) {
				return c.Next()
			}
			if isUIAsset(c.Path()) {
				return static(c)
			}
			return serveShell(c)
		})
	} else {
		app.Use(mount, func(c *fiber.Ctx) error {
			rel := strings.TrimPrefix(c.Path(), mount)
			rel = strings.TrimPrefix(rel, "/")
			if rel != "" && isUIAsset("/"+rel) {
				return static(c)
			}
			return serveShell(c)
		})
	}

	logMount(cfg, source)
	logAdminURL(cfg, services)
	return nil
}

// logAdminURL provisions a bootstrap admin token (when enabled) and logs a
// ready-to-use sign-in link. Called once at mount time. In a cluster the token
// is elected via the shared store so every replica logs and accepts the same
// value.
func logAdminURL(cfg *config.MeilingConfig, services *tokens.Services) {
	token := ProvisionSharedAdminToken(cfg, services)
	if token == "" {
		return
	}

	link := AdminSignInURL(cfg, token)
	if link == "" {
		link = AdminSignInPath(cfg) + " (set webui.addressOverride or server.publicUrl for an absolute link)"
	}
	log.Printf("webui: admin sign-in link (webui.provideAdminUrl): %s", link)
}

// reservedPrefixes are server-owned paths that must keep returning API
// responses even when the UI is mounted at the domain root.
var reservedPrefixes = []string{
	"/v1/", // reserved for an API mounted by an extension
	"/v2/",
	"/.well-known/",
	"/health",
	"/docs",
	"/openapi",
	"/schemas",
	"/swagger-ui",
	"/pks/",
}

// isUIAsset reports whether the path is a real static file (JS, CSS, images)
// rather than a client-side route that should receive the HTML shell.
func isUIAsset(path string) bool {
	base := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		base = path[i+1:]
	}
	dot := strings.LastIndex(base, ".")
	if dot <= 0 || dot == len(base)-1 {
		return false
	}
	switch strings.ToLower(base[dot+1:]) {
	case "js", "css", "map", "svg", "png", "jpg", "jpeg", "gif", "webp", "ico", "woff", "woff2", "ttf":
		return true
	default:
		return false
	}
}

func sendShell(c *fiber.Ctx, assets http.FileSystem, cfg config.WebUIConfig, maxAge int) error {
	f, err := assets.Open("index.html")
	if err != nil {
		return err
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	body := rewriteShell(raw, cfg.MountPath())
	c.Type("html", "utf-8")
	if maxAge == 0 {
		c.Set(fiber.HeaderCacheControl, "no-store, must-revalidate")
	}
	return c.Send(body)
}

// rewriteShell turns Vite's relative "./..." URLs into mount-absolute ones.
// Nested client routes like /ui/auth/signin would otherwise resolve
// ./assets/index.js as /ui/auth/assets/index.js.
func rewriteShell(html []byte, mount string) []byte {
	prefix := strings.TrimSuffix(mount, "/")
	if mount == "/" {
		prefix = ""
	}
	return []byte(strings.ReplaceAll(string(html), `="./`, `="`+prefix+`/`))
}

// isAPIPath reports whether a request belongs to the API surface rather than
// the UI's client-side routes.
func isAPIPath(path string) bool {
	for _, prefix := range reservedPrefixes {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// OwnsRoot reports whether the UI is enabled and mounted at the domain root.
// Callers use this to avoid registering a competing "GET /" handler, since
// Fiber resolves routes in registration order and the first match wins.
func OwnsRoot(cfg *config.MeilingConfig) bool {
	return cfg != nil && cfg.WebUIConfig.Enable && cfg.WebUIConfig.MountPath() == "/"
}

// IndexPath returns the URL the UI is reachable at, for logging and redirects.
func IndexPath(cfg *config.MeilingConfig) string {
	if cfg == nil || !cfg.WebUIConfig.Enable {
		return ""
	}
	mount := cfg.WebUIConfig.MountPath()
	if mount == "/" {
		return "/"
	}
	return mount + "/"
}

func logMount(cfg *config.MeilingConfig, source string) {
	log.Printf("webui: serving web interface at %s from %s", IndexPath(cfg), source)
}

// OAuth2AuthFrontendURL returns the absolute URL of the built-in web UI's
// OAuth2 authorization landing. The UI shell reads the OAuth2 query parameters
// (client_id, response_type, scope, …) and renders the consent screen (after
// signing the user in if needed), so this is a valid auth frontend. Returns ""
// when the UI is disabled or no absolute origin can be resolved.
//
// This lets an instance run the OAuth2/OIDC authorization flow entirely on the
// bundled UI, without configuring a separate external AuthFrontend.
func OAuth2AuthFrontendURL(cfg *config.MeilingConfig) string {
	index := IndexPath(cfg)
	if index == "" {
		return ""
	}
	base := cfg.WebUIConfig.PublicBaseURL(cfg.ServerConfig.PublicURL)
	if base == "" {
		return ""
	}
	return base + index
}

// AdminPanelPath returns the URL path of the admin panel entry, preserving the
// UI mount prefix. Returns "" when the UI is disabled.
func AdminPanelPath(cfg *config.MeilingConfig) string {
	index := IndexPath(cfg)
	if index == "" {
		return ""
	}
	return strings.TrimSuffix(index, "/") + "/admin/"
}

// AdminSignInPath returns the URL path of the admin sign-in entry, preserving
// the UI mount prefix (e.g. "/ui/admin/signin"). Returns "" when the UI is
// disabled. The sign-in route shows the admin gate and, on success, hands off
// to the panel at AdminPanelPath.
func AdminSignInPath(cfg *config.MeilingConfig) string {
	panel := AdminPanelPath(cfg)
	if panel == "" {
		return ""
	}
	return strings.TrimSuffix(panel, "/") + "/signin"
}

// AdminSignInURL builds an absolute link into the admin sign-in page that
// carries the given admin token in the URL fragment. The UI consumes the
// fragment on load and clears it, so the token never reaches the server as a
// query string.
func AdminSignInURL(cfg *config.MeilingConfig, token string) string {
	path := AdminSignInPath(cfg)
	if path == "" || token == "" {
		return ""
	}

	base := cfg.WebUIConfig.PublicBaseURL(cfg.ServerConfig.PublicURL)
	// autosubmit makes the link one-click: the gate signs in as soon as the
	// token is read from the fragment, without waiting for a button press.
	// header carries the configured method, so the link works whatever the
	// UI's own default is.
	frag := "#" + url.Values{"token": {token}, "header": {cfg.AdminConfig.AdminTokenMethod}, "autosubmit": {"true"}}.Encode()
	if base == "" {
		return path + frag
	}
	return base + path + frag
}
