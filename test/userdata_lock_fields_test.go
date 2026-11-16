package test

import (
	"io"
	"net/http"
	"testing"
)

func putUserData(t *testing.T, env *featureEnv, userID string, path string, body any, headers map[string]string, want int) {
	t.Helper()

	resp := mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+path, body, headers)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("PUT %s %v status = %d, want %d, body=%s", path, body, resp.StatusCode, want, string(raw))
	}
}

func TestNameLockCoversTheNameClaim(t *testing.T) {
	env := newFeatureEnv(t)

	username := "namelock" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "locked-password-123", username+"@example.com")
	sessionToken := mustCreateSessionToken(t, env)
	mustAttachUserToSession(t, env, sessionToken, userID)
	user := bearerHeaders(sessionToken)

	putUserData(t, env, userID, "/userdata", map[string]any{"name": "Before", "displayName": "Shown"}, user, http.StatusOK)
	putUserData(t, env, userID, "/userdata/lock", map[string]any{"name": true}, adminHeaders(), http.StatusOK)

	// The name claim prefers the display name, so the name lock holds it too.
	putUserData(t, env, userID, "/userdata", map[string]any{"displayName": "Other"}, user, http.StatusForbidden)
	putUserData(t, env, userID, "/userdata", map[string]any{"displayName": ""}, user, http.StatusForbidden)
	putUserData(t, env, userID, "/userdata", map[string]any{"displayName": "Shown", "lastName": "Free"}, user, http.StatusOK)
	putUserData(t, env, userID, "/userdata", map[string]any{"displayName": "By admin"}, adminHeaders(), http.StatusOK)

	putUserData(t, env, userID, "/userdata/lock", map[string]any{"display_name": true}, adminHeaders(), http.StatusOK)
	putUserData(t, env, userID, "/userdata", map[string]any{"displayName": "Other"}, user, http.StatusForbidden)
	putUserData(t, env, userID, "/userdata", map[string]any{"name": "After"}, user, http.StatusOK)
}

// With the name locked and no name or display name, the name claim is the
// primary username, so the lock has to hold the usernames as well.
func TestNameLockHoldsUsernamesWhileTheNameIsEmpty(t *testing.T) {
	env := newFeatureEnv(t)

	username := "namelockuser" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "locked-password-123", username+"@example.com")
	sessionToken := mustCreateSessionToken(t, env)
	mustAttachUserToSession(t, env, sessionToken, userID)
	user := bearerHeaders(sessionToken)

	usernames := func(t *testing.T, method string, value string, headers map[string]string, want int) {
		t.Helper()

		path := "/v2/users/" + userID + "/usernames"
		var body any = map[string]any{"username": value}
		if method == http.MethodDelete {
			path, body = path+"?username="+value, nil
		}
		resp := mustJSONRequest(t, env.server, method, path, body, headers)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s username %q status = %d, want %d, body=%s", method, value, resp.StatusCode, want, string(raw))
		}
	}
	listed := func(t *testing.T) []string {
		t.Helper()

		var names []string
		decodeJSONBody(t, mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/usernames", nil, user), &names)
		return names
	}

	putUserData(t, env, userID, "/userdata", map[string]any{"name": "", "displayName": ""}, user, http.StatusOK)
	putUserData(t, env, userID, "/userdata/lock", map[string]any{"name": true}, adminHeaders(), http.StatusOK)

	usernames(t, http.MethodPost, "added"+uniqueSuffix(), user, http.StatusForbidden)
	usernames(t, http.MethodPut, "changed"+uniqueSuffix(), user, http.StatusForbidden)
	usernames(t, http.MethodDelete, username, user, http.StatusForbidden)
	if got := listed(t); len(got) != 1 || got[0] != username {
		t.Fatalf("usernames after the refused changes = %#v, want only %q", got, username)
	}

	// An admin is not held by the lock.
	byAdmin := "byadmin" + uniqueSuffix()
	usernames(t, http.MethodPut, byAdmin, adminHeaders(), http.StatusOK)
	if got := listed(t); len(got) != 1 || got[0] != byAdmin {
		t.Fatalf("usernames after the admin change = %#v, want only %q", got, byAdmin)
	}

	// A name that is set carries the claim, so the usernames are free again.
	putUserData(t, env, userID, "/userdata", map[string]any{"name": "Set By Admin"}, adminHeaders(), http.StatusOK)
	added := "added" + uniqueSuffix()
	usernames(t, http.MethodPost, added, user, http.StatusCreated)
	usernames(t, http.MethodDelete, added, user, http.StatusOK)

	// Without the lock an empty name does not hold them either.
	putUserData(t, env, userID, "/userdata", map[string]any{"name": ""}, adminHeaders(), http.StatusOK)
	putUserData(t, env, userID, "/userdata/lock", map[string]any{}, adminHeaders(), http.StatusOK)
	usernames(t, http.MethodPut, "free"+uniqueSuffix(), user, http.StatusOK)
}

func TestUserDataLockAcceptsOnlyLockableFieldsAndBooleans(t *testing.T) {
	env := newFeatureEnv(t)

	username := "lockbody" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "locked-password-123", username+"@example.com")

	accepted := map[string]any{
		"name": true, "display_name": true, "first_name": true, "middle_name": false,
		"last_name": true, "birthday": true, "language": false, "timezone": true,
	}
	putUserData(t, env, userID, "/userdata/lock", accepted, adminHeaders(), http.StatusOK)

	for _, body := range []map[string]any{
		{"name": "true"},
		{"name": 1},
		{"name": nil},
		{"name": map[string]any{"locked": true}},
		{"nickname": true},
		{"firstName": true},
		{"name": true, "user_data_locks": false},
	} {
		resp := mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/userdata/lock", body, adminHeaders())
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PUT lock %v status = %d, want %d, body=%s", body, resp.StatusCode, http.StatusBadRequest, string(raw))
		}
	}

	resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/userdata/lock", nil, adminHeaders())
	var stored map[string]any
	decodeJSONBody(t, resp, &stored)
	if len(stored) != len(accepted) {
		t.Fatalf("stored locks = %v, want %v", stored, accepted)
	}
	for key, want := range accepted {
		if stored[key] != want {
			t.Fatalf("stored locks = %v, want %v", stored, accepted)
		}
	}
}
