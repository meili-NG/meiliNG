package test

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

type permissionTreeItem struct {
	ID        string  `json:"id"`
	Scope     string  `json:"scope"`
	Message   string  `json:"message"`
	IsPublic  bool    `json:"isPublic"`
	IsDefault bool    `json:"isDefault"`
	ParentID  *string `json:"parentId"`
}

// mustCreatePermissionViaAPI creates a permission through the admin API and
// returns it as the list endpoint reports it.
func mustCreatePermissionViaAPI(t *testing.T, env *featureEnv, scope string, parentID string) permissionTreeItem {
	t.Helper()

	body := map[string]any{"scope": scope, "isPublic": true, "message": "Access " + scope}
	if parentID != "" {
		body["parentId"] = parentID
	}
	resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/permissions/", body, adminHeaders())
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create permission %q status = %d, want %d, body=%s", scope, resp.StatusCode, http.StatusCreated, string(raw))
	}
	resp.Body.Close()

	return mustGetPermissionByScope(t, env, scope)
}

func mustGetPermissionByScope(t *testing.T, env *featureEnv, scope string) permissionTreeItem {
	t.Helper()

	resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/permissions/?scope="+url.QueryEscape(scope), nil, adminHeaders())
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("list permission %q status = %d, want %d, body=%s", scope, resp.StatusCode, http.StatusOK, string(raw))
	}
	var list struct {
		Data []permissionTreeItem `json:"data"`
	}
	decodeJSONBody(t, resp, &list)
	if len(list.Data) != 1 || list.Data[0].Scope != scope {
		t.Fatalf("list permission %q = %#v, want exactly that permission", scope, list.Data)
	}
	return list.Data[0]
}

// expectInvalidRequest asserts a 400 invalid_request and returns its message.
func expectInvalidRequest(t *testing.T, resp *http.Response, what string) string {
	t.Helper()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("%s status = %d, want %d, body=%s", what, resp.StatusCode, http.StatusBadRequest, string(raw))
	}
	var body struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	}
	decodeJSONBody(t, resp, &body)
	if body.Type != "invalid_request" {
		t.Fatalf("%s error type = %q, want invalid_request (message %q)", what, body.Type, body.Message)
	}
	return body.Message
}

func TestPermissionTreeFeatures(t *testing.T) {
	env := newFeatureEnv(t)

	suffix := uniqueSuffix()
	username := "tree" + suffix
	userID := mustCreateUser(t, env, username, "tree-password-123", username+"@example.com")
	sessionToken := mustCreateSessionToken(t, env)
	mustAttachUserToSession(t, env, sessionToken, userID)

	drive := mustCreatePermissionViaAPI(t, env, "drive."+suffix, "")
	readonly := mustCreatePermissionViaAPI(t, env, "drive.readonly."+suffix, drive.ID)
	mail := mustCreatePermissionViaAPI(t, env, "mail."+suffix, "")
	calendar := mustCreatePermissionViaAPI(t, env, "calendar."+suffix, "")

	authPath := func(client oauthClientSeed, scope string) string {
		return fmt.Sprintf("/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s",
			client.clientID.String(),
			url.QueryEscape(scope),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(userID),
		)
	}

	// consent asks whether the user has to approve scope, and what is presented.
	consent := func(t *testing.T, client oauthClientSeed, scope string) (bool, []string) {
		t.Helper()

		resp := mustJSONRequest(t, env.server, http.MethodGet, authPath(client, scope), nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("consent check status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var body struct {
			UserConsentRequired bool                 `json:"userConsentRequired"`
			Permissions         []permissionTreeItem `json:"permissions"`
		}
		decodeJSONBody(t, resp, &body)
		if body.Permissions == nil {
			t.Fatalf("consent permissions must be an array, got null")
		}

		presented := make([]string, 0, len(body.Permissions))
		for _, permission := range body.Permissions {
			presented = append(presented, permission.Scope)
		}
		slices.Sort(presented)
		return body.UserConsentRequired, presented
	}

	// grant approves scope and redeems the code, which records the consent.
	grant := func(t *testing.T, client oauthClientSeed, scope string) string {
		t.Helper()

		resp := mustJSONRequest(t, env.server, http.MethodPost, authPath(client, scope)+"&approve=true", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("authorize status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var authorizeBody struct {
			Code string `json:"code"`
		}
		decodeJSONBody(t, resp, &authorizeBody)

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"code":          {authorizeBody.Code},
			"grant_type":    {"authorization_code"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("code exchange status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var tokenBody struct {
			AccessToken string `json:"access_token"`
			Scope       string `json:"scope"`
		}
		decodeJSONBody(t, resp, &tokenBody)
		if tokenBody.Scope != scope {
			t.Fatalf("issued scope = %q, want exactly the requested %q", tokenBody.Scope, scope)
		}
		return tokenBody.AccessToken
	}

	userInfo := func(t *testing.T, accessToken string) map[string]any {
		t.Helper()

		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/userinfo", nil, bearerHeaders(accessToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("userinfo status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var body map[string]any
		decodeJSONBody(t, resp, &body)
		return body
	}

	update := func(id string, parentID string) *http.Response {
		return mustJSONRequest(t, env.server, http.MethodPut, "/v2/permissions/?id="+url.QueryEscape(id), map[string]any{
			"parentId":  parentID,
			"isPublic":  true,
			"isDefault": false,
			"message":   "moved",
		}, adminHeaders())
	}

	t.Run("permissions report their parent and visibility", func(t *testing.T) {
		if drive.ParentID != nil || !drive.IsPublic {
			t.Fatalf("top level permission = %#v, want parentId null and isPublic true", drive)
		}
		if readonly.ParentID == nil || *readonly.ParentID != drive.ID {
			t.Fatalf("child parentId = %v, want %q", readonly.ParentID, drive.ID)
		}
		if readonly.Message != "Access "+readonly.Scope {
			t.Fatalf("child message = %q, want the message sent on create", readonly.Message)
		}
	})

	t.Run("permissions without a parent need consent individually", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)

		required, presented := consent(t, client, mail.Scope)
		if !required || !slices.Equal(presented, []string{mail.Scope}) {
			t.Fatalf("first request: required=%v presented=%v, want consent for mail", required, presented)
		}

		grant(t, client, mail.Scope)

		required, presented = consent(t, client, mail.Scope)
		if required || len(presented) != 0 {
			t.Fatalf("after grant: required=%v presented=%v, want no consent", required, presented)
		}

		required, presented = consent(t, client, mail.Scope+" "+calendar.Scope)
		if !required || !slices.Equal(presented, []string{calendar.Scope}) {
			t.Fatalf("adding an unrelated scope: required=%v presented=%v, want consent for calendar only", required, presented)
		}
	})

	t.Run("parent granted then child requested needs no consent", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		grant(t, client, drive.Scope)

		required, presented := consent(t, client, readonly.Scope)
		if required || len(presented) != 0 {
			t.Fatalf("required=%v presented=%v, want no consent for a child of a granted permission", required, presented)
		}
	})

	t.Run("child granted then parent requested presents only the parent", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		grant(t, client, readonly.Scope)

		required, presented := consent(t, client, drive.Scope)
		if !required || !slices.Equal(presented, []string{drive.Scope}) {
			t.Fatalf("required=%v presented=%v, want consent for the parent only", required, presented)
		}

		required, presented = consent(t, client, drive.Scope+" "+readonly.Scope)
		if !required || !slices.Equal(presented, []string{drive.Scope}) {
			t.Fatalf("required=%v presented=%v, want the already granted child left out", required, presented)
		}
	})

	t.Run("a set with parent and child is folded for display", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		scope := readonly.Scope + " " + mail.Scope + " " + drive.Scope

		required, presented := consent(t, client, scope)
		want := []string{drive.Scope, mail.Scope}
		slices.Sort(want)
		if !required || !slices.Equal(presented, want) {
			t.Fatalf("required=%v presented=%v, want %v", required, presented, want)
		}

		// Folding is display only: the token carries what the client asked for.
		grant(t, client, scope)
	})

	t.Run("token introspection reports implied scopes", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		accessToken := grant(t, client, drive.Scope)

		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?access_token="+url.QueryEscape(accessToken), nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("tokeninfo status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var info struct {
			Scope        string `json:"scope"`
			ImpliedScope string `json:"implied_scope"`
		}
		decodeJSONBody(t, resp, &info)
		if info.Scope != drive.Scope {
			t.Fatalf("tokeninfo scope = %q, want %q", info.Scope, drive.Scope)
		}
		if info.ImpliedScope != drive.Scope+" "+readonly.Scope {
			t.Fatalf("tokeninfo implied_scope = %q, want %q", info.ImpliedScope, drive.Scope+" "+readonly.Scope)
		}
	})

	t.Run("create rejects an unknown parent", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/permissions/", map[string]any{
			"scope":    "orphan." + suffix,
			"parentId": "00000000-0000-4000-8000-000000000000",
		}, adminHeaders())
		expectInvalidRequest(t, resp, "create with unknown parent")
	})

	t.Run("update replaces parent visibility and message", func(t *testing.T) {
		moved := mustCreatePermissionViaAPI(t, env, "moved."+suffix, "")

		resp := mustJSONRequest(t, env.server, http.MethodPut, "/v2/permissions/?id="+url.QueryEscape(moved.ID), map[string]any{
			"parentId":  mail.ID,
			"isPublic":  false,
			"isDefault": false,
			"message":   "Moved under mail",
		}, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("update status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		got := mustGetPermissionByScope(t, env, moved.Scope)
		if got.ParentID == nil || *got.ParentID != mail.ID || got.IsPublic || got.Message != "Moved under mail" || got.Scope != moved.Scope {
			t.Fatalf("after update = %#v", got)
		}

		resp = update(moved.ID, "")
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("move to top level status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		got = mustGetPermissionByScope(t, env, moved.Scope)
		if got.ParentID != nil || !got.IsPublic || got.Message != "moved" {
			t.Fatalf("after move to top level = %#v", got)
		}
	})

	t.Run("update is admin only", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodPut, "/v2/permissions/?id="+url.QueryEscape(mail.ID), map[string]any{
			"parentId":  "",
			"isPublic":  false,
			"isDefault": true,
			"message":   "hijacked",
		}, bearerHeaders(sessionToken))
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("non-admin update status = %d, want 401 or 403", resp.StatusCode)
		}
		if got := mustGetPermissionByScope(t, env, mail.Scope); got.Message == "hijacked" || !got.IsPublic || got.IsDefault {
			t.Fatalf("non-admin update changed the permission: %#v", got)
		}
	})

	t.Run("update rejects a cycle", func(t *testing.T) {
		expectInvalidRequest(t, update(drive.ID, drive.ID), "own parent")
		expectInvalidRequest(t, update(drive.ID, readonly.ID), "parent under its child")
		expectInvalidRequest(t, update(drive.ID, "00000000-0000-4000-8000-000000000000"), "unknown parent")

		if got := mustGetPermissionByScope(t, env, drive.Scope); got.ParentID != nil {
			t.Fatalf("rejected updates changed the parent to %q", *got.ParentID)
		}
	})

	t.Run("a claim gated on email is released by an ancestor grant", func(t *testing.T) {
		ensurePermissionScope(t, env, "openid")
		email := mustGetPermissionByScope(t, env, "email")
		account := mustCreatePermissionViaAPI(t, env, "account."+suffix, "")

		resp := update(email.ID, account.ID)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("move email under account status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		withoutEmail := userInfo(t, grant(t, seedOAuthClient(t, env, true, true), "openid"))
		if _, ok := withoutEmail["email"]; ok {
			t.Fatalf("email released without any grant covering it: %#v", withoutEmail)
		}

		withAncestor := userInfo(t, grant(t, seedOAuthClient(t, env, true, true), "openid "+account.Scope))
		if withAncestor["email"] != username+"@example.com" {
			t.Fatalf("email = %v, want it released through the ancestor grant", withAncestor["email"])
		}
	})

	t.Run("delete rejects a permission with children", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodDelete, "/v2/permissions/?id="+url.QueryEscape(drive.ID), nil, adminHeaders())
		if message := expectInvalidRequest(t, resp, "delete parent"); !strings.Contains(message, "child permissions") {
			t.Fatalf("delete parent message = %q, want it to mention child permissions", message)
		}

		for _, id := range []string{readonly.ID, drive.ID} {
			resp = mustJSONRequest(t, env.server, http.MethodDelete, "/v2/permissions/?id="+url.QueryEscape(id), nil, adminHeaders())
			if resp.StatusCode != http.StatusOK {
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				t.Fatalf("delete leaf status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
			}
			resp.Body.Close()
		}
	})
}
