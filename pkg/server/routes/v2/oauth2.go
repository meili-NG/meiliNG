package v2

import (
	"github.com/danielgtaylor/huma/v2"
)

// registerOAuth2Routes registers all OAuth2 routes under /v2/oauth2
func (r *V2Router) registerOAuth2Routes(v2API huma.API) {
	oauth2API := huma.NewGroup(v2API, "/oauth2")

	// Register core OAuth2 routes
	r.registerOAuth2CoreRoutes(oauth2API)

	// Register token info routes
	r.registerOAuth2TokenInfoRoutes(oauth2API)

	// Register the audience catalog (admin-only, nested group)
	r.registerOAuth2AudienceRoutes(oauth2API)
}
