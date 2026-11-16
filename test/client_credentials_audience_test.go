package test

import (
	"net/http"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestClientCredentialsNeedsAnAssignedAudience(t *testing.T) {
	env := newM2MAdminEnv(t, config.OAuth2Config{})
	client := seedOAuthClient(t, env, false, true)
	if err := env.db.Exec("DELETE FROM oauth_client_audiences WHERE client_id = ?", client.clientID).Error; err != nil {
		t.Fatalf("clear audiences: %v", err)
	}

	for _, audience := range []string{"https://anything.example.com", testClientAudiences[0], testAdminAudience} {
		resp := requestClientCredentials(t, env, client, audience)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("audience %q for a client with none assigned status = %d, want %d", audience, resp.StatusCode, http.StatusBadRequest)
		}
	}
}
