package test

import (
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// A distribution adds private claims to access tokens; they land under the
// claims namespace and never replace a claim core sets.
func TestAccessTokenClaimsHook(t *testing.T) {
	env := newM2MAdminEnv(t, config.OAuth2Config{})
	client := seedOAuthClient(t, env, false, true)
	mustAssignAudience(t, env, client, testAdminAudience)

	t.Cleanup(tokens.AccessTokenClaims.Reset)
	var seenClient, seenUser string
	tokens.AccessTokenClaims.Override(func(clientID, userID string) map[string]any {
		seenClient, seenUser = clientID, userID
		return map[string]any{"tier": "internal", "token_type": "forged"}
	})

	token := mustClientCredentialsToken(t, env, client, testAdminAudience)
	ns := env.app.TokenServices().JWT().ClaimsNamespace()
	claims := jwtClaims(t, token)
	if claims[ns+"tier"] != "internal" {
		t.Fatalf("claims = %v, want %stier", claims, ns)
	}
	if claims[ns+"token_type"] != tokens.TokenTypeAccessToken {
		t.Fatalf("token_type = %v, the hook replaced a core claim", claims[ns+"token_type"])
	}
	if seenClient != client.clientID.String() || seenUser != "" {
		t.Fatalf("hook called with client %q user %q", seenClient, seenUser)
	}
}
