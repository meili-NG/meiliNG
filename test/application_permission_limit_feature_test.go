package test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

type applicationPermissionLimit struct {
	Limited     bool                 `json:"limited"`
	Permissions []permissionTreeItem `json:"permissions"`
}

func (l applicationPermissionLimit) scopes() []string {
	scopes := make([]string, 0, len(l.Permissions))
	for _, permission := range l.Permissions {
		scopes = append(scopes, permission.Scope)
	}
	return scopes
}

func TestApplicationPermissionLimitFeatures(t *testing.T) {
	// AllowCreate lets the test user create a client as its owner.
	env := newFeatureEnvWithOAuth2Config(t, config.OAuth2Config{AllowCreate: true})

	suffix := uniqueSuffix()
	username := "limit" + suffix
	userID := mustCreateUser(t, env, username, "limit-password-123", username+"@example.com")
	sessionToken := mustCreateSessionToken(t, env)
	mustAttachUserToSession(t, env, sessionToken, userID)

	drive := mustCreatePermissionViaAPI(t, env, "drive."+suffix, "")
	readonly := mustCreatePermissionViaAPI(t, env, "drive.readonly."+suffix, drive.ID)
	metadata := mustCreatePermissionViaAPI(t, env, "drive.readonly.metadata."+suffix, readonly.ID)
	mail := mustCreatePermissionViaAPI(t, env, "mail."+suffix, "")

	limitPath := func(client oauthClientSeed) string {
		return "/v2/apps/" + client.clientID.String() + "/permissions/"
	}

	decodeLimit := func(t *testing.T, resp *http.Response, what string) applicationPermissionLimit {
		t.Helper()

		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("%s status = %d, want %d, body=%s", what, resp.StatusCode, http.StatusOK, string(raw))
		}
		var limit applicationPermissionLimit
		decodeJSONBody(t, resp, &limit)
		if limit.Permissions == nil {
			t.Fatalf("%s permissions must be an array, got null", what)
		}
		return limit
	}

	getLimit := func(t *testing.T, client oauthClientSeed) applicationPermissionLimit {
		t.Helper()
		// Read without the trailing slash, written with it: both spellings are served.
		return decodeLimit(t, mustJSONRequest(t, env.server, http.MethodGet, strings.TrimSuffix(limitPath(client), "/"), nil, adminHeaders()), "get limit")
	}

	setLimit := func(t *testing.T, client oauthClientSeed, limited bool, permissionIDs ...string) applicationPermissionLimit {
		t.Helper()

		if permissionIDs == nil {
			permissionIDs = []string{}
		}
		resp := mustJSONRequest(t, env.server, http.MethodPut, limitPath(client), map[string]any{
			"limited":       limited,
			"permissionIds": permissionIDs,
		}, adminHeaders())
		return decodeLimit(t, resp, "set limit")
	}

	authPath := func(client oauthClientSeed, scope string, extra string) string {
		return fmt.Sprintf("/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s%s",
			client.clientID.String(),
			url.QueryEscape(scope),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(userID),
			extra,
		)
	}

	authorize := func(client oauthClientSeed, scope string, extra string) *http.Response {
		return mustJSONRequest(t, env.server, http.MethodPost, authPath(client, scope, extra)+"&approve=true", nil, bearerHeaders(sessionToken))
	}

	mustAuthorize := func(t *testing.T, client oauthClientSeed, scope string, extra string) string {
		t.Helper()

		resp := authorize(client, scope, extra)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("authorize %q status = %d, want %d, body=%s", scope, resp.StatusCode, http.StatusOK, string(raw))
		}
		var body struct {
			Code string `json:"code"`
		}
		decodeJSONBody(t, resp, &body)
		if body.Code == "" {
			t.Fatalf("authorize %q returned no code", scope)
		}
		return body.Code
	}

	token := func(client oauthClientSeed, values url.Values) *http.Response {
		values.Set("client_id", client.clientID.String())
		if client.secret != "" {
			values.Set("client_secret", client.secret)
		}
		return mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", values, nil)
	}

	type tokenBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}

	mustToken := func(t *testing.T, client oauthClientSeed, values url.Values) tokenBody {
		t.Helper()

		resp := token(client, values)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("token (%s) status = %d, want %d, body=%s", values.Get("grant_type"), resp.StatusCode, http.StatusOK, string(raw))
		}
		var body tokenBody
		decodeJSONBody(t, resp, &body)
		if body.AccessToken == "" {
			t.Fatalf("token (%s) returned no access token", values.Get("grant_type"))
		}
		return body
	}

	// grant approves scope and redeems the code, which records the consent.
	grant := func(t *testing.T, client oauthClientSeed, scope string, extra string) tokenBody {
		t.Helper()
		return mustToken(t, client, url.Values{
			"grant_type": {"authorization_code"},
			"code":       {mustAuthorize(t, client, scope, extra)},
		})
	}

	expectInvalidScope := func(t *testing.T, resp *http.Response, what string) {
		t.Helper()

		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want %d, body=%s", what, resp.StatusCode, http.StatusBadRequest, string(raw))
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("%s body is not JSON: %s", what, string(raw))
		}
		if body["error"] != "invalid_scope" {
			t.Fatalf("%s error = %v, want invalid_scope, body=%s", what, body["error"], string(raw))
		}
		for _, issued := range []string{"code", "tokens", "access_token", "device_code"} {
			if _, ok := body[issued]; ok {
				t.Fatalf("%s issued %s although it was rejected, body=%s", what, issued, string(raw))
			}
		}
	}

	consentLogs := func(t *testing.T, client oauthClientSeed) int64 {
		t.Helper()

		var count int64
		if err := env.db.Model(&database.ApplicationConsentLog{}).Where("application_id = ?", client.clientID).Count(&count).Error; err != nil {
			t.Fatalf("count consent logs: %v", err)
		}
		return count
	}

	startDevice := func(client oauthClientSeed, scope string) *http.Response {
		return mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/device", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"scope":         {scope},
		}, nil)
	}

	approveDevice := func(userCode string) *http.Response {
		return mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/device/authorize", url.Values{
			"user_code": {userCode},
			"user_id":   {userID},
			"approve":   {"true"},
		}, bearerHeaders(sessionToken))
	}

	// seedOAuthClient sets AllowAnyPermission.
	t.Run("a client that allows any permission is unlimited", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)

		if limit := getLimit(t, client); limit.Limited || len(limit.Permissions) != 0 {
			t.Fatalf("stored client limit = %#v, want unlimited with no permissions", limit)
		}

		// The allowed set is kept but not applied while the flag is off.
		limit := setLimit(t, client, false, readonly.ID)
		if limit.Limited || !slices.Equal(limit.scopes(), []string{readonly.Scope}) {
			t.Fatalf("set limit = %#v, want unlimited holding %q", limit, readonly.Scope)
		}
		if got := getLimit(t, client); got.Limited || !slices.Equal(got.scopes(), []string{readonly.Scope}) {
			t.Fatalf("get limit = %#v, want what was set", got)
		}

		scope := drive.Scope + " " + mail.Scope
		if got := grant(t, client, scope, ""); got.Scope != scope {
			t.Fatalf("issued scope = %q, want %q", got.Scope, scope)
		}
	})

	t.Run("an application row written without the flag is limited", func(t *testing.T) {
		client := oauthClientSeed{clientID: uuid.New(), redirectURI: "https://client.example.com/callback", secret: "super-secret-value"}
		row := database.Application{
			ApplicationFields: models.ApplicationFields{ID: client.clientID, Name: "Written Directly"},
			OauthClient: &database.OauthClient{
				RedirectURIs: []database.OauthRedirectURI{{
					OAuthRedirectURIFields: models.OAuthRedirectURIFields{ID: uuid.New(), ClientID: client.clientID, URI: client.redirectURI},
				}},
				Credentials: []database.OauthCredential{{
					OAuthCredentialFields: models.OAuthCredentialFields{ID: uuid.New(), ClientID: client.clientID, Secret: client.secret},
				}},
			},
		}
		if err := env.db.Create(&row).Error; err != nil {
			t.Fatalf("create application row: %v", err)
		}

		if limit := getLimit(t, client); !limit.Limited || len(limit.Permissions) != 0 {
			t.Fatalf("limit of a row written without the flag = %#v, want limited with no permissions of its own", limit)
		}
		// Default permissions are copied in only on creation through the API, so this row has none.
		for _, scope := range []string{mail.Scope, drive.Scope, "openid " + mail.Scope, "openid profile"} {
			expectInvalidScope(t, authorize(client, scope, ""), "authorize "+scope)
		}

		// The stored defaults are the restricted state, whatever writes the row.
		inserted := oauthClientSeed{clientID: uuid.New()}
		if err := env.db.Exec("INSERT INTO applications (id, name, icon_url) VALUES (?, 'Inserted Directly', '')", inserted.clientID).Error; err != nil {
			t.Fatalf("insert application: %v", err)
		}
		if err := env.db.Exec("INSERT INTO oauth_clients (application_id) VALUES (?)", inserted.clientID).Error; err != nil {
			t.Fatalf("insert oauth client: %v", err)
		}
		if limit := getLimit(t, inserted); !limit.Limited {
			t.Fatalf("limit of an inserted row = %#v, want limited", limit)
		}
		var flags database.OauthClient
		if err := env.db.First(&flags, "application_id = ?", inserted.clientID).Error; err != nil {
			t.Fatalf("read oauth client: %v", err)
		}
		if flags.IsPublicClient || flags.BypassConsent {
			t.Fatalf("flags of an inserted oauth client = %+v, want none set", flags.OAuthClientFields)
		}
	})

	t.Run("a limited client may request an allowed permission and what it contains", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		limit := setLimit(t, client, true, readonly.ID, readonly.ID)
		if !limit.Limited || !slices.Equal(limit.scopes(), []string{readonly.Scope}) {
			t.Fatalf("set limit = %#v, want limited to %q once", limit, readonly.Scope)
		}
		if limit.Permissions[0].ID != readonly.ID || limit.Permissions[0].ParentID == nil || *limit.Permissions[0].ParentID != drive.ID {
			t.Fatalf("limit permission = %#v, want the permission as the permission list reports it", limit.Permissions[0])
		}

		resp := mustJSONRequest(t, env.server, http.MethodGet, authPath(client, readonly.Scope, ""), nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("consent check status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		scope := readonly.Scope + " " + metadata.Scope
		if got := grant(t, client, scope, ""); got.Scope != scope {
			t.Fatalf("issued scope = %q, want %q", got.Scope, scope)
		}
	})

	t.Run("requesting outside the limit is invalid_scope and records nothing", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		setLimit(t, client, true, readonly.ID)

		for _, scope := range []string{drive.Scope, mail.Scope, readonly.Scope + " " + drive.Scope} {
			resp := mustJSONRequest(t, env.server, http.MethodGet, authPath(client, scope, ""), nil, bearerHeaders(sessionToken))
			expectInvalidScope(t, resp, "consent check for "+scope)
			expectInvalidScope(t, authorize(client, scope, ""), "authorize "+scope)
			implicit := strings.Replace(authPath(client, scope, ""), "response_type=code", "response_type=token", 1)
			expectInvalidScope(t, mustJSONRequest(t, env.server, http.MethodPost, implicit, nil, bearerHeaders(sessionToken)), "implicit authorize "+scope)
			expectInvalidScope(t, startDevice(client, scope), "device authorization for "+scope)
			expectInvalidScope(t, token(client, url.Values{
				"grant_type": {"client_credentials"},
				"audience":   {"https://api.example.com"},
				"scope":      {scope},
			}), "client_credentials for "+scope)
		}

		if count := consentLogs(t, client); count != 0 {
			t.Fatalf("consent logs = %d, want none after rejected requests", count)
		}
	})

	t.Run("limited with an empty set rejects everything", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		if limit := setLimit(t, client, true); !limit.Limited || len(limit.Permissions) != 0 {
			t.Fatalf("set limit = %#v, want limited to nothing", limit)
		}

		for _, scope := range []string{drive.Scope, readonly.Scope, metadata.Scope, mail.Scope} {
			expectInvalidScope(t, authorize(client, scope, ""), "authorize "+scope)
		}
		if count := consentLogs(t, client); count != 0 {
			t.Fatalf("consent logs = %d, want none", count)
		}
	})

	t.Run("an unknown permission id changes nothing", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		setLimit(t, client, true, readonly.ID)

		for _, unknown := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
			resp := mustJSONRequest(t, env.server, http.MethodPut, limitPath(client), map[string]any{
				"limited":       false,
				"permissionIds": []string{mail.ID, unknown},
			}, adminHeaders())
			expectInvalidRequest(t, resp, "set limit with "+unknown)
		}

		if limit := getLimit(t, client); !limit.Limited || !slices.Equal(limit.scopes(), []string{readonly.Scope}) {
			t.Fatalf("limit after rejected updates = %#v, want it unchanged", limit)
		}
	})

	t.Run("an unknown client is not found", func(t *testing.T) {
		missing := oauthClientSeed{clientID: uuid.New()}
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			resp := mustJSONRequest(t, env.server, method, limitPath(missing), map[string]any{
				"limited":       true,
				"permissionIds": []string{},
			}, adminHeaders())
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("%s unknown client status = %d, want %d", method, resp.StatusCode, http.StatusNotFound)
			}
		}
	})

	t.Run("only an admin reads or changes the limit", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		if err := env.db.Model(&database.Application{}).Where("id = ?", client.clientID).Update("owner_id", userID).Error; err != nil {
			t.Fatalf("set client owner: %v", err)
		}
		setLimit(t, client, true, readonly.ID)

		// Without any token the session middleware answers 400 before the admin check.
		for who, headers := range map[string]map[string]string{"owner": bearerHeaders(sessionToken), "anonymous": nil} {
			for _, method := range []string{http.MethodGet, http.MethodPut} {
				resp := mustJSONRequest(t, env.server, method, limitPath(client), map[string]any{
					"limited":       false,
					"permissionIds": []string{drive.ID},
				}, headers)
				resp.Body.Close()
				denied := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
				if who == "anonymous" {
					denied = denied || resp.StatusCode == http.StatusBadRequest
				}
				if !denied {
					t.Fatalf("%s %s status = %d, want it denied", who, method, resp.StatusCode)
				}
			}
		}

		// The owner's own client update must not reach the flag under any spelling.
		for _, body := range []map[string]any{
			{"name": "Renamed by owner"},
			{"name": "Renamed by owner", "limited": false, "allowAnyPermission": true, "allow_any_permission": true, "permissionIds": []string{drive.ID}},
		} {
			resp := mustJSONRequest(t, env.server, http.MethodPut, "/v2/apps/"+client.clientID.String()+"/", body, bearerHeaders(sessionToken))
			resp.Body.Close()
		}

		if limit := getLimit(t, client); !limit.Limited || !slices.Equal(limit.scopes(), []string{readonly.Scope}) {
			t.Fatalf("limit after non-admin attempts = %#v, want it unchanged", limit)
		}
		expectInvalidScope(t, authorize(client, drive.Scope, ""), "authorize after non-admin attempts")

		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/apps/"+client.clientID.String()+"/", nil, bearerHeaders(sessionToken))
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := strings.ToLower(string(raw))
		if resp.StatusCode != http.StatusOK || strings.Contains(body, "limit") || strings.Contains(body, "allowany") || strings.Contains(body, "allow_any") {
			t.Fatalf("client as its owner sees it: status = %d, body=%s, want no limit field", resp.StatusCode, string(raw))
		}
	})

	t.Run("deleting an allowed permission leaves the client limited", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		doomed := mustCreatePermissionViaAPI(t, env, "doomed."+suffix, "")
		setLimit(t, client, true, doomed.ID)

		resp := mustJSONRequest(t, env.server, http.MethodDelete, "/v2/permissions/?id="+url.QueryEscape(doomed.ID), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("delete allowed permission status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		if limit := getLimit(t, client); !limit.Limited || len(limit.Permissions) != 0 {
			t.Fatalf("limit after delete = %#v, want still limited, to nothing", limit)
		}
		expectInvalidScope(t, authorize(client, mail.Scope, ""), "authorize after the last allowed permission was deleted")
	})

	t.Run("a grant from before the limit was tightened yields nothing new", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		setLimit(t, client, true, drive.ID)

		granted := grant(t, client, drive.Scope, "&access_type=offline")
		if granted.RefreshToken == "" {
			t.Fatalf("offline grant returned no refresh token")
		}
		pendingCode := mustAuthorize(t, client, drive.Scope, "")
		logs := consentLogs(t, client)

		setLimit(t, client, true, readonly.ID)

		expectInvalidScope(t, token(client, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {granted.RefreshToken},
		}), "refresh after tightening")
		expectInvalidScope(t, token(client, url.Values{
			"grant_type": {"authorization_code"},
			"code":       {pendingCode},
		}), "code exchange after tightening")
		if count := consentLogs(t, client); count != logs {
			t.Fatalf("consent logs = %d, want %d: a rejected exchange must not record consent", count, logs)
		}

		// The rejection did not consume the token: it works once it is allowed again.
		setLimit(t, client, true, drive.ID)
		if refreshed := mustToken(t, client, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {granted.RefreshToken},
		}); refreshed.Scope != drive.Scope {
			t.Fatalf("refreshed scope = %q, want %q", refreshed.Scope, drive.Scope)
		}
	})

	t.Run("a device grant is checked when started approved and redeemed", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		setLimit(t, client, true, readonly.ID)

		start := func(t *testing.T) (string, string) {
			t.Helper()

			resp := startDevice(client, readonly.Scope)
			if resp.StatusCode != http.StatusOK {
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				t.Fatalf("device authorization status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
			}
			var body struct {
				DeviceCode string `json:"device_code"`
				UserCode   string `json:"user_code"`
			}
			decodeJSONBody(t, resp, &body)
			return body.DeviceCode, body.UserCode
		}

		_, userCode := start(t)
		setLimit(t, client, true)
		expectInvalidScope(t, approveDevice(userCode), "device approval after tightening")
		if count := consentLogs(t, client); count != 0 {
			t.Fatalf("consent logs = %d, want none after a rejected approval", count)
		}

		setLimit(t, client, true, readonly.ID)
		deviceCode, userCode := start(t)
		resp := approveDevice(userCode)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("device approval status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		setLimit(t, client, true)
		redeem := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceCode},
		}
		expectInvalidScope(t, token(client, redeem), "device token after tightening")

		setLimit(t, client, true, drive.ID)
		if got := mustToken(t, client, redeem); got.Scope != readonly.Scope {
			t.Fatalf("device token scope = %q, want %q", got.Scope, readonly.Scope)
		}
	})

	t.Run("include_granted_scopes adds earlier grants and drops the ones no longer allowed", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)
		grant(t, client, mail.Scope, "")

		want := readonly.Scope + " " + mail.Scope
		if got := grant(t, client, readonly.Scope, "&include_granted_scopes=true"); got.Scope != want {
			t.Fatalf("issued scope = %q, want the request plus the earlier grant %q", got.Scope, want)
		}
		if got := grant(t, client, readonly.Scope, ""); got.Scope != readonly.Scope {
			t.Fatalf("issued scope = %q, want only %q without include_granted_scopes", got.Scope, readonly.Scope)
		}

		setLimit(t, client, true, readonly.ID)

		if got := grant(t, client, readonly.Scope, "&include_granted_scopes=true"); got.Scope != readonly.Scope {
			t.Fatalf("issued scope = %q, want the no longer allowed %q dropped", got.Scope, mail.Scope)
		}
	})

	// createClient makes a client through the API, with one secret, as headers' caller.
	createClient := func(t *testing.T, headers map[string]string) oauthClientSeed {
		t.Helper()

		client := oauthClientSeed{redirectURI: "https://client.example.com/callback"}
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/apps/?user_id="+url.QueryEscape(userID), map[string]any{
			"name":         "Created Through The API",
			"redirectURIs": []string{client.redirectURI},
			"privacy":      "https://client.example.com/privacy",
			"terms":        "https://client.example.com/terms",
		}, headers)
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create client status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		var created struct {
			ID string `json:"id"`
		}
		decodeJSONBody(t, resp, &created)
		client.clientID = uuid.MustParse(created.ID)

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/apps/"+created.ID+"/oauth2/secrets/?user_id="+url.QueryEscape(userID), map[string]any{
			"notes": "default permission test",
		}, headers)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create client secret status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var secret struct {
			ClientSecret string `json:"client_secret"`
		}
		decodeJSONBody(t, resp, &secret)
		client.secret = secret.ClientSecret
		return client
	}

	updatePermission := func(permission permissionTreeItem, isDefault bool, headers map[string]string) *http.Response {
		parentID := ""
		if permission.ParentID != nil {
			parentID = *permission.ParentID
		}
		return mustJSONRequest(t, env.server, http.MethodPut, "/v2/permissions/?id="+url.QueryEscape(permission.ID), map[string]any{
			"parentId":  parentID,
			"isPublic":  permission.IsPublic,
			"isDefault": isDefault,
			"message":   permission.Message,
		}, headers)
	}

	setDefault := func(t *testing.T, permission permissionTreeItem, isDefault bool) {
		t.Helper()

		resp := updatePermission(permission, isDefault, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("set default of %q status = %d, want %d, body=%s", permission.Scope, resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()
		if got := mustGetPermissionByScope(t, env, permission.Scope); got.IsDefault != isDefault || got.Message != permission.Message {
			t.Fatalf("permission after setting default to %v = %#v", isDefault, got)
		}
	}

	t.Run("a client created through the API starts allowed the default permissions", func(t *testing.T) {
		seeded := "openid profile email phone address offline_access"
		for _, scope := range strings.Fields(seeded) {
			if got := mustGetPermissionByScope(t, env, scope); !got.IsDefault {
				t.Fatalf("seeded permission %q is not a default permission: %#v", scope, got)
			}
		}
		if mail.IsDefault {
			t.Fatalf("permission created without isDefault = %#v, want it not default", mail)
		}

		for who, headers := range map[string]map[string]string{"owner": bearerHeaders(sessionToken), "admin": adminHeaders()} {
			client := createClient(t, headers)
			want := slices.Sorted(slices.Values(strings.Fields(seeded)))
			if limit := getLimit(t, client); !limit.Limited || !slices.Equal(limit.scopes(), want) {
				t.Fatalf("limit of a client created by its %s = %#v, want limited to %v", who, limit, want)
			}

			if got := grant(t, client, seeded, ""); got.Scope != seeded {
				t.Fatalf("issued scope = %q, want %q", got.Scope, seeded)
			}
			expectInvalidScope(t, authorize(client, mail.Scope, ""), "authorize a non-default permission as a client created by its "+who)

			// The copied defaults are the client's own rows: replacing the set drops them.
			if limit := setLimit(t, client, true, mail.ID); !slices.Equal(limit.scopes(), []string{mail.Scope}) {
				t.Fatalf("set limit = %#v, want only %q", limit, mail.Scope)
			}
			if got := grant(t, client, mail.Scope, ""); got.Scope != mail.Scope {
				t.Fatalf("issued scope = %q, want %q", got.Scope, mail.Scope)
			}
			expectInvalidScope(t, authorize(client, "openid "+mail.Scope, ""), "authorize a default permission the client no longer holds")
		}
	})

	t.Run("a default permission reaches only applications created while it is default", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/permissions/", map[string]any{
			"scope":     "open." + suffix,
			"isPublic":  true,
			"isDefault": true,
			"message":   "Access open",
		}, adminHeaders())
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create default permission status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		resp.Body.Close()
		open := mustGetPermissionByScope(t, env, "open."+suffix)
		if !open.IsDefault {
			t.Fatalf("permission created with isDefault = %#v, want it default", open)
		}
		child := mustCreatePermissionViaAPI(t, env, "open.child."+suffix, open.ID)
		leaf := mustCreatePermissionViaAPI(t, env, "open.child.leaf."+suffix, child.ID)

		// An application that existed before the flag does not get it.
		existing := seedOAuthClient(t, env, true, true)
		setLimit(t, existing, true)
		expectInvalidScope(t, authorize(existing, open.Scope, ""), "authorize a default permission created after the application")

		client := createClient(t, adminHeaders())
		if limit := getLimit(t, client); !slices.Contains(limit.scopes(), open.Scope) {
			t.Fatalf("limit = %#v, want %q copied in", limit, open.Scope)
		}
		scope := open.Scope + " " + child.Scope + " " + leaf.Scope
		granted := grant(t, client, scope, "&access_type=offline")
		if granted.Scope != scope || granted.RefreshToken == "" {
			t.Fatalf("grant = %#v, want %q with a refresh token", granted, scope)
		}
		expectInvalidScope(t, authorize(client, drive.Scope, ""), "authorize outside the copied permissions")

		// Turning the flag off leaves applications that already have it alone.
		setDefault(t, open, false)
		refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {granted.RefreshToken}}
		if refreshed := mustToken(t, client, refresh); refreshed.Scope != scope {
			t.Fatalf("refreshed scope = %q, want %q after the default flag was turned off", refreshed.Scope, scope)
		}
		later := createClient(t, adminHeaders())
		expectInvalidScope(t, authorize(later, open.Scope, ""), "authorize as an application created after the default flag was turned off")
	})

	t.Run("only an admin makes a permission default", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/permissions/", map[string]any{
			"scope":     "selfmade." + suffix,
			"isPublic":  true,
			"isDefault": true,
		}, bearerHeaders(sessionToken))
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("non-admin create status = %d, want 401 or 403", resp.StatusCode)
		}
		var created int64
		if err := env.db.Model(&database.Permission{}).Where("scope = ?", "selfmade."+suffix).Count(&created).Error; err != nil {
			t.Fatalf("count permissions: %v", err)
		}
		if created != 0 {
			t.Fatalf("non-admin created a permission")
		}

		resp = updatePermission(mail, true, bearerHeaders(sessionToken))
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("non-admin update status = %d, want 401 or 403", resp.StatusCode)
		}
		if got := mustGetPermissionByScope(t, env, mail.Scope); got.IsDefault {
			t.Fatalf("non-admin made %q default: %#v", mail.Scope, got)
		}

		client := createClient(t, bearerHeaders(sessionToken))
		expectInvalidScope(t, authorize(client, mail.Scope, ""), "authorize after the non-admin attempts")
	})
}
