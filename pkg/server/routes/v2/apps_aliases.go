package v2

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

const (
	applicationAliasRoot = "/v2/oauth2/clients"
	applicationRoot      = "/v2/apps"
)

// applicationAliasSegments maps the segment after the application id on an
// alias path to its place under /v2/apps/{app_id}. Every other segment keeps
// its name.
var applicationAliasSegments = map[string]string{
	"redirectUris": "oauth2/redirect_uris",
	"secrets":      "oauth2/secrets",
	"audiences":    "oauth2/audiences",
	"auth":         "oauth2/auth",
}

// registerApplicationAliases answers every path under /v2/oauth2/clients with a
// redirect to its /v2/apps path. OPTIONS is left out, so a preflight is not redirected.
func (r *V2Router) registerApplicationAliases() {
	for _, method := range fiber.DefaultMethods {
		if method != fiber.MethodOptions {
			r.fiberApp.Add(method, applicationAliasRoot+"/*", redirectApplicationAlias)
		}
	}
}

// redirectApplicationAlias builds the Location from the request path and query
// alone, one validated segment at a time, so it always stays under /v2/apps.
func redirectApplicationAlias(c *fiber.Ctx) error {
	path := c.Path()
	if len(path) < len(applicationAliasRoot) || !strings.EqualFold(path[:len(applicationAliasRoot)], applicationAliasRoot) {
		return fiber.ErrNotFound
	}
	tail := path[len(applicationAliasRoot):]
	if tail != "" && tail[0] != '/' {
		return fiber.ErrNotFound
	}

	location := applicationRoot
	if segments := strings.TrimSuffix(strings.TrimPrefix(tail, "/"), "/"); segments != "" {
		for i, segment := range strings.Split(segments, "/") {
			if !isApplicationAliasSegment(segment) {
				return fiber.ErrNotFound
			}
			if mapped, ok := applicationAliasSegments[segment]; ok && i == 1 {
				segment = mapped
			}
			location += "/" + segment
		}
	}
	if strings.HasSuffix(tail, "/") {
		location += "/"
	}

	if query := string(c.Context().URI().QueryString()); query != "" {
		if strings.ContainsAny(query, "\r\n") {
			return fiber.ErrNotFound
		}
		location += "?" + query
	}

	return c.Redirect(location, fiber.StatusTemporaryRedirect)
}

// isApplicationAliasSegment accepts only unreserved URL characters, which rules
// out empty and dot segments, backslashes and percent-encoding.
func isApplicationAliasSegment(segment string) bool {
	if segment == "" || segment == "." || segment == ".." {
		return false
	}
	for _, r := range segment {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_', r == '~':
		default:
			return false
		}
	}
	return true
}
