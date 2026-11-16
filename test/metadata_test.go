package test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/pkg/metadata"
)

// Admins keep free-form metadata on applications, permissions and audiences,
// and plugins read the same data through pkg/metadata.
func TestRecordMetadata(t *testing.T) {
	env := newFeatureEnv(t)
	client := seedOAuthClient(t, env, false, true)
	permissionID := seedPermission(t, env, "meta."+uniqueSuffix())
	audienceID := mustRegisterCatalogAudience(t, env, "https://meta-"+uniqueSuffix()+".example.com")

	for _, tc := range []struct {
		kind metadata.Kind
		id   string
		path string
	}{
		{metadata.Applications, client.clientID.String(), "/v2/apps/" + client.clientID.String() + "/metadata/"},
		{metadata.Permissions, permissionID.String(), "/v2/permissions/metadata/?id=" + permissionID.String()},
		{metadata.Audiences, audienceID, "/v2/oauth2/audiences/" + audienceID + "/metadata/"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			send := func(method string, body any, headers map[string]string) int {
				resp := mustJSONRequest(t, env.server, method, tc.path, body, headers)
				resp.Body.Close()
				return resp.StatusCode
			}
			if status := send(http.MethodPut, map[string]any{"plan": "pro", "limits": map[string]any{"rps": 10.0}}, adminHeaders()); status >= 300 {
				t.Fatalf("PUT = %d", status)
			}
			if status := send(http.MethodPatch, map[string]any{"limits": map[string]any{"burst": 20.0}}, adminHeaders()); status >= 300 {
				t.Fatalf("PATCH = %d", status)
			}

			resp := mustJSONRequest(t, env.server, http.MethodGet, tc.path, nil, adminHeaders())
			var got map[string]any
			decodeJSONBody(t, resp, &got)
			limits, _ := got["limits"].(map[string]any)
			if got["plan"] != "pro" || limits["rps"] != 10.0 || limits["burst"] != 20.0 {
				t.Fatalf("GET = %v, want the PUT merged with the PATCH", got)
			}

			stored, err := metadata.Get(tc.kind, tc.id)
			if err != nil || stored["plan"] != "pro" {
				t.Fatalf("metadata.Get = %v, %v", stored, err)
			}

			if status := send(http.MethodGet, nil, bearerHeaders(mustCreateSessionToken(t, env))); status < 400 {
				t.Fatalf("a user session reading metadata = %d, want refused", status)
			}
		})
	}

	if _, err := metadata.Get(metadata.Applications, uuid.NewString()); err == nil {
		t.Fatal("metadata of a missing application")
	}
}
