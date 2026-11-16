package test

import (
	"io"
	"net/http"
	"testing"
)

func TestUserDataLocksAreEnforced(t *testing.T) {
	env := newFeatureEnv(t)

	username := "locked" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "locked-password-123", username+"@example.com")
	sessionToken := mustCreateSessionToken(t, env)
	mustAttachUserToSession(t, env, sessionToken, userID)

	put := func(t *testing.T, path string, body map[string]any, headers map[string]string, want int) {
		t.Helper()

		resp := mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+path, body, headers)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("PUT %s %v status = %d, want %d, body=%s", path, body, resp.StatusCode, want, string(raw))
		}
	}
	user := bearerHeaders(sessionToken)

	put(t, "/userdata", map[string]any{"name": "Before", "firstName": "Before"}, user, http.StatusOK)
	put(t, "/userdata/lock", map[string]any{"name": true, "first_name": true}, adminHeaders(), http.StatusOK)

	put(t, "/userdata", map[string]any{"name": "After"}, user, http.StatusForbidden)
	put(t, "/userdata", map[string]any{"firstName": "After"}, user, http.StatusForbidden)

	// A client that sends its whole form back changes only what differs.
	put(t, "/userdata", map[string]any{"name": "Before", "lastName": "Free"}, user, http.StatusOK)
	put(t, "/userdata", map[string]any{"firstName": "By admin"}, adminHeaders(), http.StatusOK)

	resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/userdata", nil, user)
	var data struct {
		Name      string `json:"name"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}
	decodeJSONBody(t, resp, &data)
	if data.Name != "Before" || data.FirstName != "By admin" || data.LastName != "Free" {
		t.Fatalf("user data = %+v, want name Before, firstName By admin, lastName Free", data)
	}

	put(t, "/userdata/lock", map[string]any{}, adminHeaders(), http.StatusOK)
	put(t, "/userdata", map[string]any{"name": "After"}, user, http.StatusOK)
}
