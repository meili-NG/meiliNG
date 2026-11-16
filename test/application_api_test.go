package test

import (
	"encoding/json"
	"fmt"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

type applicationFixture struct {
	env     *featureEnv
	ownerID string
	owner   map[string]string
	otherID string
	other   map[string]string
}

func newApplicationFixture(t *testing.T) applicationFixture {
	t.Helper()

	// AllowCreate lets a signed-in user create an application as its owner.
	env := newFeatureEnvWithOAuth2Config(t, config.OAuth2Config{AllowCreate: true})
	signIn := func(prefix string) (string, map[string]string) {
		username := prefix + uniqueSuffix()
		userID := mustCreateUser(t, env, username, "application-password-123", username+"@example.com")
		session := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, session, userID)
		return userID, bearerHeaders(session)
	}

	f := applicationFixture{env: env}
	f.ownerID, f.owner = signIn("appowner")
	f.otherID, f.other = signIn("appother")
	return f
}

// status sends the request and returns the status code and the raw body.
func (f applicationFixture) status(t *testing.T, method string, path string, body any, headers map[string]string) (int, string) {
	t.Helper()

	resp := mustJSONRequest(t, f.env.server, method, path, body, headers)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(raw)
}

// must sends the request, requires the status and decodes the body into target when it is given.
func (f applicationFixture) must(t *testing.T, want int, method string, path string, body any, headers map[string]string, target any) {
	t.Helper()

	status, raw := f.status(t, method, path, body, headers)
	if status != want {
		t.Fatalf("%s %s status = %d, want %d, body=%s", method, path, status, want, raw)
	}
	if target != nil {
		if err := json.Unmarshal([]byte(raw), target); err != nil {
			t.Fatalf("%s %s decode %s: %v", method, path, raw, err)
		}
	}
}

// create registers an application owned by the fixture's owner and returns its id.
func (f applicationFixture) create(t *testing.T, name string, redirectURI string) string {
	t.Helper()

	var created struct {
		ID string `json:"id"`
	}
	f.must(t, http.StatusCreated, http.MethodPost, "/v2/apps/?user_id="+f.ownerID, map[string]any{
		"name":         name,
		"redirectURIs": []string{redirectURI},
		"privacy":      "https://app.example.com/privacy",
		"terms":        "https://app.example.com/terms",
	}, f.owner, &created)
	if created.ID == "" {
		t.Fatal("created application has no id")
	}
	return created.ID
}

func TestApplicationOperationsAreDocumentedAtTheirPaths(t *testing.T) {
	env := newFeatureEnv(t)

	var document struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	decodeJSONBody(t, mustJSONRequest(t, env.server, http.MethodGet, "/openapi.json", nil, nil), &document)

	for _, want := range []struct{ method, path, operationID string }{
		{"get", "/v2/apps/", "getApplications"},
		{"post", "/v2/apps/", "createApplication"},
		{"get", "/v2/apps/{app_id}/", "getApplication"},
		{"put", "/v2/apps/{app_id}/", "updateApplication"},
		{"delete", "/v2/apps/{app_id}/", "deleteApplication"},
		{"post", "/v2/apps/{app_id}/unauthorize", "unauthorizeApplication"},
		{"get", "/v2/apps/{app_id}/permissions/", "getApplicationPermissions"},
		{"put", "/v2/apps/{app_id}/permissions/", "setApplicationPermissions"},
		{"get", "/v2/apps/{app_id}/oauth2/redirect_uris/", "getOAuth2ClientRedirectUris"},
		{"post", "/v2/apps/{app_id}/oauth2/redirect_uris/", "createOAuth2ClientRedirectUri"},
		{"delete", "/v2/apps/{app_id}/oauth2/redirect_uris/", "deleteOAuth2ClientRedirectUri"},
		{"get", "/v2/apps/{app_id}/oauth2/secrets/", "getOAuth2ClientSecrets"},
		{"post", "/v2/apps/{app_id}/oauth2/secrets/", "createOAuth2ClientSecret"},
		{"delete", "/v2/apps/{app_id}/oauth2/secrets/", "deleteOAuth2ClientSecret"},
		{"get", "/v2/apps/{app_id}/oauth2/audiences/", "getOAuth2ClientAudiences"},
		{"post", "/v2/apps/{app_id}/oauth2/audiences/", "assignOAuth2ClientAudience"},
		{"delete", "/v2/apps/{app_id}/oauth2/audiences/", "unassignOAuth2ClientAudience"},
		{"get", "/v2/apps/{app_id}/oauth2/auth/", "authEndpointCall"},
		{"post", "/v2/apps/{app_id}/oauth2/auth/", "authorizeClient"},
	} {
		if got := document.Paths[want.path][want.method].OperationID; got != want.operationID {
			t.Errorf("%s %s operationId = %q, want %q", want.method, want.path, got, want.operationID)
		}
	}

	for path := range document.Paths {
		if strings.Contains(path, "/oauth2/clients") {
			t.Errorf("alias path %s is listed in the OpenAPI document", path)
		}
	}
}

func TestApplicationOwnerAndAdminOperations(t *testing.T) {
	f := newApplicationFixture(t)
	id := f.create(t, "Owned Application", "https://owned.example.com/callback")
	base := "/v2/apps/" + id

	var secret struct {
		ID string `json:"id"`
	}
	f.must(t, http.StatusOK, http.MethodPost, base+"/oauth2/secrets/?user_id="+f.ownerID, map[string]any{"notes": "owner"}, f.owner, &secret)

	ownerOnly := []struct {
		method, path string
		body         any
	}{
		{http.MethodPut, base + "/", map[string]any{"name": "Taken Over"}},
		{http.MethodDelete, base + "/", nil},
		{http.MethodGet, base + "/oauth2/secrets/?user_id=%s", nil},
		{http.MethodPost, base + "/oauth2/secrets/?user_id=%s", map[string]any{"notes": "stolen"}},
		{http.MethodDelete, base + "/oauth2/secrets/?user_id=%s&secret_id=" + secret.ID, nil},
		{http.MethodGet, base + "/oauth2/redirect_uris/?user_id=%s", nil},
		{http.MethodPost, base + "/oauth2/redirect_uris/?user_id=%s", map[string]any{"redirect_uri": "https://other.example.com/callback"}},
		{http.MethodDelete, base + "/oauth2/redirect_uris/?user_id=%s&redirectUriId=" + secret.ID, nil},
	}
	for _, op := range ownerOnly {
		path := op.path
		if strings.Contains(path, "%s") {
			path = fmt.Sprintf(path, f.otherID)
		}
		if status, raw := f.status(t, op.method, path, op.body, f.other); status != http.StatusUnauthorized || !strings.Contains(raw, "not owner") {
			t.Fatalf("another user %s %s status = %d, body=%s, want 401 not owner", op.method, path, status, raw)
		}
		// Naming the owner in user_id does not help a session that is not theirs.
		if strings.Contains(op.path, "%s") {
			path = fmt.Sprintf(op.path, f.ownerID)
			if status, raw := f.status(t, op.method, path, op.body, f.other); status < 400 {
				t.Fatalf("another user %s %s status = %d, body=%s, want it denied", op.method, path, status, raw)
			}
		}
	}

	adminOnly := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, base + "/permissions/", nil},
		{http.MethodPut, base + "/permissions/", map[string]any{"limited": false, "permissionIds": []string{}}},
		{http.MethodGet, base + "/oauth2/audiences/", nil},
		{http.MethodPost, base + "/oauth2/audiences/", map[string]any{"audience_id": secret.ID}},
		{http.MethodDelete, base + "/oauth2/audiences/?audienceId=" + secret.ID, nil},
	}
	for _, op := range adminOnly {
		for who, headers := range map[string]map[string]string{"owner": f.owner, "another user": f.other} {
			if status, raw := f.status(t, op.method, op.path, op.body, headers); status != http.StatusUnauthorized && status != http.StatusForbidden {
				t.Fatalf("%s %s %s status = %d, body=%s, want 401 or 403", who, op.method, op.path, status, raw)
			}
		}
	}

	// Nothing above changed the application, and its owner and an admin still manage it.
	var limit struct {
		Limited bool `json:"limited"`
	}
	f.must(t, http.StatusOK, http.MethodGet, base+"/permissions/", nil, adminHeaders(), &limit)
	if !limit.Limited {
		t.Fatal("an application created through the API is not limited")
	}

	var secrets []struct {
		ID string `json:"id"`
	}
	f.must(t, http.StatusOK, http.MethodGet, base+"/oauth2/secrets/?user_id="+f.ownerID, nil, f.owner, &secrets)
	if len(secrets) != 1 || secrets[0].ID != secret.ID {
		t.Fatalf("secrets after the denied requests = %#v, want the owner's one", secrets)
	}

	f.must(t, http.StatusOK, http.MethodPut, base+"/", map[string]any{"name": "Renamed By Owner"}, f.owner, nil)
	var application struct {
		Name string `json:"name"`
	}
	f.must(t, http.StatusOK, http.MethodGet, base+"/", nil, f.owner, &application)
	if application.Name != "Renamed By Owner" {
		t.Fatalf("name = %q, want the owner's update", application.Name)
	}

	// A signed-in user lists what they own or authorized, never every application.
	var listed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	f.must(t, http.StatusOK, http.MethodGet, "/v2/apps/?page=1&size=100&all=true", nil, f.other, &listed)
	if len(listed.Data) != 0 {
		t.Fatalf("another user lists %#v with all=true, want nothing", listed.Data)
	}
	f.must(t, http.StatusForbidden, http.MethodGet, "/v2/apps/?owned=true&user_id="+f.ownerID, nil, f.other, nil)
	f.must(t, http.StatusOK, http.MethodGet, "/v2/apps/?page=1&size=100&owned=true", nil, f.owner, &listed)
	if len(listed.Data) != 1 || listed.Data[0].ID != id {
		t.Fatalf("owner lists %#v, want the owned application", listed.Data)
	}

	f.must(t, http.StatusOK, http.MethodDelete, base+"/", nil, f.owner, nil)
}

func TestApplicationRedirectURIValidation(t *testing.T) {
	f := newApplicationFixture(t)
	ensurePermissionScope(t, f.env, "openid")
	id := f.create(t, "Redirect Application", "https://mysite.example.com/callback")

	for _, invalid := range []string{"", "not a uri", "javascript:alert(1)"} {
		status, raw := f.status(t, http.MethodPost, "/v2/apps/"+id+"/oauth2/redirect_uris/?user_id="+f.ownerID, map[string]any{"redirect_uri": invalid}, f.owner)
		if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
			t.Fatalf("register redirect uri %q status = %d, body=%s, want it refused", invalid, status, raw)
		}
	}

	authPath := func(redirectURI string) string {
		return fmt.Sprintf("/v2/apps/%s/oauth2/auth/?response_type=code&scope=openid&redirect_uri=%s&user_id=%s&approve=true", id, url.QueryEscape(redirectURI), f.ownerID)
	}
	for _, redirectURI := range []string{
		"https://evil.example.com/callback",
		"https://mysite.example.com.evil.example/callback",
		"https://mysite.example.com/other",
		"http://mysite.example.com/callback",
		"https://mysite.example.com:8443/callback",
		// U+0130 lowercases to "i", but a browser resolves this host elsewhere.
		"https://mysİte.example.com/callback",
		"https://mysite.exаmple.com/callback",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if status, raw := f.status(t, method, authPath(redirectURI), nil, f.owner); status != http.StatusBadRequest || !strings.Contains(raw, "redirect_uri is invalid") {
				t.Fatalf("%s authorize with redirect_uri %q status = %d, body=%s, want 400 redirect_uri is invalid", method, redirectURI, status, raw)
			}
		}
	}

	for _, redirectURI := range []string{"https://mysite.example.com/callback", "https://MYSITE.example.com/callback"} {
		var issued struct {
			Code string `json:"code"`
		}
		f.must(t, http.StatusOK, http.MethodPost, authPath(redirectURI), nil, f.owner, &issued)
		if issued.Code == "" {
			t.Fatalf("authorize with redirect_uri %q issued no code", redirectURI)
		}
	}
}

func TestDeletingAnApplicationRemovesWhatHangsOffIt(t *testing.T) {
	f := newApplicationFixture(t)
	ensurePermissionScope(t, f.env, "openid")
	extra := mustCreatePermissionViaAPI(t, f.env, "delete.extra."+uniqueSuffix(), "")

	const name, redirectURI = "Deleted Application", "https://deleted.example.com/callback"
	id := f.create(t, name, redirectURI)
	base := "/v2/apps/" + id

	var secret struct {
		ClientSecret string `json:"client_secret"`
	}
	f.must(t, http.StatusOK, http.MethodPost, base+"/oauth2/secrets/?user_id="+f.ownerID, map[string]any{"notes": "doomed"}, f.owner, &secret)

	var audience struct {
		ID string `json:"id"`
	}
	f.must(t, http.StatusCreated, http.MethodPost, "/v2/oauth2/audiences/", map[string]any{"audience": "https://deleted-api.example.com"}, adminHeaders(), &audience)
	f.must(t, http.StatusCreated, http.MethodPost, base+"/oauth2/audiences/", map[string]any{"audience_id": audience.ID}, adminHeaders(), nil)
	f.must(t, http.StatusOK, http.MethodPut, base+"/permissions/", map[string]any{"limited": true, "permissionIds": []string{extra.ID, mustGetPermissionByScope(t, f.env, "openid").ID}}, adminHeaders(), nil)

	authPath := func(applicationID string) string {
		return fmt.Sprintf("/v2/apps/%s/oauth2/auth/?response_type=code&scope=openid&redirect_uri=%s&user_id=%s&approve=true", applicationID, url.QueryEscape(redirectURI), f.ownerID)
	}
	var issued struct {
		Code string `json:"code"`
	}
	f.must(t, http.StatusOK, http.MethodPost, authPath(id), nil, f.owner, &issued)

	exchange := func(applicationID string, clientSecret string, code string) *http.Response {
		return mustFormRequest(t, f.env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {applicationID},
			"client_secret": {clientSecret},
			"code":          {code},
			"grant_type":    {"authorization_code"},
		}, nil)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	decodeJSONBody(t, exchange(id, secret.ClientSecret, issued.Code), &tokens)
	if tokens.AccessToken == "" {
		t.Fatal("no access token before the delete")
	}
	f.must(t, http.StatusOK, http.MethodGet, "/v2/oauth2/userinfo", nil, bearerHeaders(tokens.AccessToken), nil)

	// A second code stays unredeemed until the application is gone.
	f.must(t, http.StatusOK, http.MethodPost, authPath(id), nil, f.owner, &issued)

	rows := func(t *testing.T, applicationID string) map[string]int64 {
		t.Helper()

		counts := map[string]int64{}
		for table, column := range map[string]string{
			"oauth_clients":            "application_id",
			"oauth_redirect_uris":      "client_id",
			"oauth_credentials":        "client_id",
			"oauth_client_audiences":   "client_id",
			"application_permissions":  "application_id",
			"application_consent_logs": "application_id",
			"application_policies":     "application_id",
		} {
			var count int64
			if err := f.env.db.Table(table).Where(column+" = ?", applicationID).Count(&count).Error; err != nil {
				t.Fatalf("count %s: %v", table, err)
			}
			counts[table] = count
		}
		return counts
	}
	for table, count := range rows(t, id) {
		if count == 0 {
			t.Fatalf("%s holds no row of the application before the delete", table)
		}
	}
	var grantedPermissions int64
	countGrantedPermissions := func() int64 {
		if err := f.env.db.Table("application_consent_logs_permissions").Count(&grantedPermissions).Error; err != nil {
			t.Fatalf("count consent log permissions: %v", err)
		}
		return grantedPermissions
	}
	if countGrantedPermissions() == 0 {
		t.Fatal("no consent log permission before the delete")
	}

	f.must(t, http.StatusOK, http.MethodDelete, base+"/", nil, f.owner, nil)

	for table, count := range rows(t, id) {
		if count != 0 {
			t.Errorf("%s still holds %d rows of the deleted application", table, count)
		}
	}
	if countGrantedPermissions() != 0 {
		t.Errorf("%d consent log permissions outlive the only application that had consent", grantedPermissions)
	}

	f.must(t, http.StatusNotFound, http.MethodGet, base+"/", nil, adminHeaders(), nil)
	f.must(t, http.StatusNotFound, http.MethodGet, base+"/oauth2/secrets/", nil, adminHeaders(), nil)
	f.must(t, http.StatusNotFound, http.MethodGet, base+"/permissions/", nil, adminHeaders(), nil)
	f.must(t, http.StatusNotFound, http.MethodPost, authPath(id), nil, f.owner, nil)
	if status, raw := f.status(t, http.MethodGet, "/v2/oauth2/userinfo", nil, bearerHeaders(tokens.AccessToken)); status < 400 {
		t.Fatalf("userinfo with a token of the deleted application status = %d, body=%s", status, raw)
	}
	for what, resp := range map[string]*http.Response{
		"the outstanding code": exchange(id, secret.ClientSecret, issued.Code),
		"client_credentials": mustFormRequest(t, f.env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {id},
			"client_secret": {secret.ClientSecret},
			"grant_type":    {"client_credentials"},
			"audience":      {"https://deleted-api.example.com"},
		}, nil),
	} {
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatalf("%s of the deleted application status = %d, want it refused", what, resp.StatusCode)
		}
	}

	// The audience is free again, and so are the name and the redirect URI.
	f.must(t, http.StatusOK, http.MethodDelete, "/v2/oauth2/audiences/"+audience.ID+"/", nil, adminHeaders(), nil)

	again := f.create(t, name, redirectURI)
	if again == id {
		t.Fatal("the new application reuses the deleted id")
	}
	var defaults int64
	if err := f.env.db.Model(&database.Permission{}).Where("is_default = ?", true).Count(&defaults).Error; err != nil {
		t.Fatal(err)
	}
	for table, count := range rows(t, again) {
		want := int64(1)
		switch table {
		case "oauth_clients", "oauth_redirect_uris", "application_policies":
		case "application_permissions": // only the default permissions, copied in on creation
			want = defaults
		default:
			want = 0
		}
		if count != want {
			t.Errorf("%s holds %d rows of the new application, want %d", table, count, want)
		}
	}
	f.must(t, http.StatusOK, http.MethodPost, authPath(again), nil, f.owner, &issued)
	if issued.Code == "" {
		t.Fatal("the application registered again issued no code")
	}
}

// A user owns at most oauth2.maxApplications applications, unless an admin set
// a cap for that user; admins creating applications are not capped.
func TestApplicationCountCap(t *testing.T) {
	env := newFeatureEnvWithOAuth2Config(t, config.OAuth2Config{AllowCreate: true, MaxApplications: 2})
	username := "capped" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "capped-password-123", username+"@example.com")
	session := mustCreateSessionToken(t, env)
	mustAttachUserToSession(t, env, session, userID)
	f := applicationFixture{env: env}

	create := func(headers map[string]string) int {
		status, _ := f.status(t, http.MethodPost, "/v2/apps/?user_id="+userID, map[string]any{
			"name": "Capped", "redirectURIs": []string{"https://capped.example.com/callback"},
			"privacy": "https://capped.example.com/privacy", "terms": "https://capped.example.com/terms",
		}, headers)
		return status
	}
	setCap := func(headers map[string]string, limit int) int {
		status, _ := f.status(t, http.MethodPut, "/v2/users/"+userID+"/", map[string]any{"maxApplications": limit}, headers)
		return status
	}
	user := bearerHeaders(session)

	for i := range 2 {
		if status := create(user); status != http.StatusCreated {
			t.Fatalf("application %d = %d, want 201", i+1, status)
		}
	}
	if status := create(user); status != http.StatusForbidden {
		t.Fatalf("application over the configured cap = %d, want 403", status)
	}

	if status := setCap(user, 100); status != http.StatusForbidden {
		t.Fatalf("a user raising their own cap = %d, want 403", status)
	}
	if status := setCap(adminHeaders(), 3); status >= 300 {
		t.Fatalf("admin setting a cap = %d", status)
	}
	if status := create(user); status != http.StatusCreated {
		t.Fatalf("application under the user's own cap = %d, want 201", status)
	}
	if status := create(user); status != http.StatusForbidden {
		t.Fatalf("application over the user's own cap = %d, want 403", status)
	}

	if status := create(adminHeaders()); status != http.StatusCreated {
		t.Fatalf("admin creating past the cap = %d, want 201", status)
	}

	if status := setCap(adminHeaders(), -1); status >= 300 {
		t.Fatalf("admin clearing the cap = %d", status)
	}
	var got struct {
		MaxApplications *int `json:"maxApplications"`
	}
	f.must(t, http.StatusOK, http.MethodGet, "/v2/users/"+userID+"/", nil, adminHeaders(), &got)
	if got.MaxApplications != nil {
		t.Fatalf("cleared cap = %d, want none", *got.MaxApplications)
	}
}
