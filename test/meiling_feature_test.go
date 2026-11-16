package test

import (
	meiling "github.com/meili-NG/meiliNG/v2"

	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

type featureEnv struct {
	app    *meiling.Meiling
	server *fiber.App
	db     *gorm.DB
}

type oauthClientSeed struct {
	clientID    uuid.UUID
	redirectURI string
	secret      string
}

func uniqueSuffix() string {
	return strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", ""))[:12]
}

func newFeatureEnv(t *testing.T) *featureEnv {
	return newFeatureEnvWithOAuth2Config(t, config.OAuth2Config{})
}

func TestHealthEndpoint(t *testing.T) {
	env := newFeatureEnv(t)

	resp := mustJSONRequest(t, env.server, http.MethodGet, "/health", nil, nil)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("health status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
	}

	var body map[string]string
	decodeJSONBody(t, resp, &body)
	if body["status"] != "OK" {
		t.Fatalf("health body status = %q, want %q", body["status"], "OK")
	}
	if body["name"] != "Meiling Test" {
		t.Fatalf("health body name = %q, want %q", body["name"], "Meiling Test")
	}
}

func newFeatureEnvWithOAuth2Config(t *testing.T, oauth2Cfg config.OAuth2Config) *featureEnv {
	t.Helper()
	return newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) {
		if oauth2Cfg.ConsentFrontends == nil {
			oauth2Cfg.ConsentFrontends = cfg.OAuth2Config.ConsentFrontends
		}
		cfg.OAuth2Config = oauth2Cfg
	})
}

// newFeatureEnvWithConfig builds a feature env whose config is adjusted by
// mutate before the app starts, for settings read once at startup.
func newFeatureEnvWithConfig(t *testing.T, mutate func(*config.MeilingConfig)) *featureEnv {
	t.Helper()

	database.ResetInstance()
	dir := t.TempDir()
	cfg := config.MeilingConfig{
		InstanceConfig: config.InstanceConfig{Name: "Meiling Test"},
		ServerConfig:   config.ServerConfig{PublicURL: "https://api.example.com"},
		OAuth2Config:   config.OAuth2Config{ConsentFrontends: []string{"https://accounts.example.com/auth"}},
		DatabaseConfig: config.DatabaseConfig{
			Type: "sqlite",
			DSN:  filepath.Join(dir, "meiling-test.sqlite"),
		},
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:      "RS256",
			PrivateKeyPath: filepath.Join(dir, "jwt.key"),
			PublicKeyPath:  filepath.Join(dir, "jwt.pub"),
		}},
		AuthConfig: config.AuthConfig{SignUp: config.SignUpConfig{
			AllowSignUp:               true,
			EmailRequired:             true,
			EmailVerificationRequired: false,
			UsernameRequired:          false,
			PhoneRequired:             false,
			PhoneVerificationRequired: false,
			PreventDisposableEmails:   false,
		}},
		AdminConfig: config.AdminConfig{
			AdminTokenMethod: "Meiling-Admin-Token",
			AdminTokens:      []string{"test-admin-token"},
			Accept:           []string{config.AdminAcceptToken, config.AdminAcceptBootstrap},
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	appInstance, err := meiling.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	server, err := appInstance.GetServer()
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}

	db, err := database.GetDatabase()
	if err != nil {
		t.Fatalf("GetDatabase: %v", err)
	}

	meilingErrors.SetConfig(&meilingErrors.Config{})

	return &featureEnv{
		app:    appInstance,
		server: server,
		db:     db,
	}
}

func mustJSONRequest(t *testing.T, app *fiber.App, method string, path string, body any, headers map[string]string) *http.Response {
	t.Helper()

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test(%s %s): %v", method, path, err)
	}
	return resp
}

func mustFormRequest(t *testing.T, app *fiber.App, method string, path string, body url.Values, headers map[string]string) *http.Response {
	t.Helper()

	encoded := ""
	if body != nil {
		encoded = body.Encode()
	}

	req := httptest.NewRequest(method, path, strings.NewReader(encoded))
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test(%s %s): %v", method, path, err)
	}
	return resp
}

func decodeJSONBody(t *testing.T, resp *http.Response, target any) {
	t.Helper()
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
}

func adminHeaders() map[string]string {
	return map[string]string{
		"Authorization": "Meiling-Admin-Token test-admin-token",
	}
}

func bearerHeaders(token string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + token,
	}
}

func mergeHeaders(base map[string]string, extra map[string]string) map[string]string {
	headers := make(map[string]string, len(base)+len(extra))
	for key, value := range base {
		headers[key] = value
	}
	for key, value := range extra {
		headers[key] = value
	}
	return headers
}

func parseResourceIDFromLocation(t *testing.T, location string) string {
	t.Helper()

	id := strings.TrimPrefix(location, "/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 {
		t.Fatalf("invalid location: %q", location)
	}
	return parts[len(parts)-1]
}

func mustCreateUser(t *testing.T, env *featureEnv, username string, password string, email string) string {
	t.Helper()

	resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/", map[string]any{
		"username": username,
		"password": password,
		"emails": []map[string]any{{
			"email":    email,
			"verified": true,
		}},
	}, adminHeaders())
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create user status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
	}

	location := resp.Header.Get("Location")
	resp.Body.Close()
	if location == "" {
		t.Fatalf("expected create user location header")
	}

	return parseResourceIDFromLocation(t, location)
}

func mustCreateSessionToken(t *testing.T, env *featureEnv) string {
	t.Helper()

	resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/sessions/", nil, nil)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create session status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
	}

	var body struct {
		Token string `json:"token"`
	}
	decodeJSONBody(t, resp, &body)
	if body.Token == "" {
		t.Fatalf("expected non-empty session token")
	}

	return body.Token
}

func mustAttachUserToSession(t *testing.T, env *featureEnv, token string, userID string) {
	t.Helper()

	manager := env.app.TokenServices().Session()
	payload, err := manager.Get(token)
	if err != nil {
		t.Fatalf("session manager get: %v", err)
	}

	payload.AddUser(userID)
	if err := manager.Set(token, payload); err != nil {
		t.Fatalf("session manager set: %v", err)
	}
}

func mustCompletePasswordSignIn(t *testing.T, env *featureEnv, sessionToken string, username string, password string, extraHeaders map[string]string) {
	t.Helper()

	headers := mergeHeaders(bearerHeaders(sessionToken), extraHeaders)

	resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
		"username": username,
	}, headers)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("signin status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
	}

	var signinBody struct {
		RequestToken string `json:"requestToken"`
	}
	decodeJSONBody(t, resp, &signinBody)
	if signinBody.RequestToken == "" {
		t.Fatalf("expected challenge token for signin")
	}

	resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", nil, nil)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("issue challenge status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
	}
	resp.Body.Close()

	resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", map[string]any{
		"response": password,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("validate challenge status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
	}
	resp.Body.Close()

	resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
		"username":       username,
		"challengeToken": signinBody.RequestToken,
	}, headers)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("signin complete status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
	}
	resp.Body.Close()
}

func ensurePermissionScope(t *testing.T, env *featureEnv, scope string) uuid.UUID {
	t.Helper()

	var permission database.Permission
	if err := env.db.First(&permission, "scope = ?", scope).Error; err == nil {
		return permission.ID
	}

	return seedPermission(t, env, scope)
}

// ensureAudience registers an audience in the catalog, reusing it if a
// previous seed already created it.
func ensureAudience(t *testing.T, env *featureEnv, audience string) database.OauthAudience {
	t.Helper()

	var existing database.OauthAudience
	if err := env.db.First(&existing, "audience = ?", audience).Error; err == nil {
		return existing
	}

	record := database.OauthAudience{
		OAuthAudienceFields: models.OAuthAudienceFields{
			ID:       uuid.New(),
			Audience: audience,
		},
	}
	if err := env.db.Create(&record).Error; err != nil {
		t.Fatalf("Create audience: %v", err)
	}
	return record
}

// testClientAudiences are assigned to every seeded confidential client so
// client_credentials tests can request them.
var testClientAudiences = []string{
	"https://api.example.com",
	"https://secondary.example.com",
	"https://api1.example.com",
	"https://api2.example.com",
}

func seedOAuthClient(t *testing.T, env *featureEnv, withRedirect bool, withSecret bool) oauthClientSeed {
	t.Helper()

	clientID := uuid.New()
	client := &database.OauthClient{
		OAuthClientFields: models.OAuthClientFields{
			// A client seeded without a secret is a public client.
			IsPublicClient: !withSecret,
		},
	}
	application := database.Application{
		ApplicationFields: models.ApplicationFields{
			ID:         clientID,
			Name:       "Feature Test Client",
			IconURL:    "https://client.example.com/icon.png",
			IsVerified: true,
			// Tests that do not exercise the per-application permission limit run without it.
			AllowAnyPermission: true,
		},
		OauthClient: client,
	}

	if withRedirect {
		client.RedirectURIs = []database.OauthRedirectURI{{
			OAuthRedirectURIFields: models.OAuthRedirectURIFields{
				ID:       uuid.New(),
				ClientID: clientID,
				URI:      "https://client.example.com/callback",
			},
		}}
	}

	secret := ""
	if withSecret {
		secret = "super-secret-value"
		client.Credentials = []database.OauthCredential{{
			OAuthCredentialFields: models.OAuthCredentialFields{
				ID:       uuid.New(),
				ClientID: clientID,
				Secret:   secret,
			},
		}}

		// client_credentials only issues audiences an admin assigned.
		for _, audience := range testClientAudiences {
			client.Audiences = append(client.Audiences, database.OauthClientAudience{
				OAuthClientAudienceFields: models.OAuthClientAudienceFields{
					ID:         uuid.New(),
					ClientID:   clientID,
					AudienceID: ensureAudience(t, env, audience).ID,
				},
			})
		}
	}

	if err := env.db.Create(&application).Error; err != nil {
		t.Fatalf("Create application: %v", err)
	}

	return oauthClientSeed{
		clientID:    clientID,
		redirectURI: "https://client.example.com/callback",
		secret:      secret,
	}
}

func seedPermission(t *testing.T, env *featureEnv, scope string) uuid.UUID {
	t.Helper()

	permissionID := uuid.New()
	permission := database.Permission{
		PermissionFields: models.PermissionFields{
			ID:       permissionID,
			Scope:    scope,
			Message:  "Feature test permission",
			IsPublic: true,
		},
	}

	if err := env.db.Create(&permission).Error; err != nil {
		t.Fatalf("Create permission: %v", err)
	}

	return permissionID
}

func TestFeatureRoutes(t *testing.T) {
	env := newFeatureEnv(t)

	t.Run("signup config respects origin checks", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/auth/signup", nil, map[string]string{
			"Origin": "https://accounts.example.com",
		})

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var body map[string]any
		decodeJSONBody(t, resp, &body)
		if body["allowSignup"] != true || body["emailRequired"] != true {
			t.Fatalf("unexpected signup config body: %#v", body)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/auth/signup", nil, map[string]string{
			"Origin": "https://evil.example.com",
		})

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("disallowed origin status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["message"] != "origin is not allowed" {
			t.Fatalf("unexpected origin error body: %#v", errBody)
		}
	})

	t.Run("session create validate and admin debug work end to end", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/sessions/", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("create session status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var createBody struct {
			Token          string    `json:"token"`
			ExpiresAt      time.Time `json:"expiresAt"`
			RenewableAfter time.Time `json:"renewableAfter"`
		}
		decodeJSONBody(t, resp, &createBody)
		if createBody.Token == "" {
			t.Fatalf("expected non-empty session token")
		}
		if createBody.ExpiresAt.IsZero() {
			t.Fatal("expected session creation response to include expiresAt")
		}
		if createBody.RenewableAfter.IsZero() {
			t.Fatal("expected session creation response to include renewableAfter")
		}
		if !createBody.RenewableAfter.Before(createBody.ExpiresAt) {
			t.Fatalf("expected renewableAfter before expiresAt, got renewableAfter=%v expiresAt=%v", createBody.RenewableAfter, createBody.ExpiresAt)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/", nil, map[string]string{
			"Authorization": "Bearer " + createBody.Token,
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("validate session status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		var validateBody struct {
			Renewable bool `json:"renewable"`
		}
		decodeJSONBody(t, resp, &validateBody)
		if validateBody.Renewable {
			t.Fatal("expected fresh session to report renewable=false until it is within the 36h renewal window")
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/debug/?token="+url.QueryEscape(createBody.Token), nil, map[string]string{
			"Authorization": "Meiling-Admin-Token test-admin-token",
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("session debug status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var debugBody map[string]any
		decodeJSONBody(t, resp, &debugBody)
		if debugBody["tid"] == "" {
			t.Fatalf("expected debug response to include token tid: %#v", debugBody)
		}
		if debugBody["sid"] == "" {
			t.Fatalf("expected debug response to include session sid: %#v", debugBody)
		}
	})

	t.Run("session create with bearer renews same session sid, rotates tid, and extends signin log expiry", func(t *testing.T) {
		username := "renewuser" + uniqueSuffix()
		email := username + "@example.com"
		password := "renew-password-123"
		userID := mustCreateUser(t, env, username, password, email)

		sessionToken := mustCreateSessionToken(t, env)
		mustCompletePasswordSignIn(t, env, sessionToken, username, password, nil)

		manager := env.app.TokenServices().Session()
		originalPayload, err := manager.Get(sessionToken)
		if err != nil {
			t.Fatalf("get original session payload: %v", err)
		}
		originalPayload.ExpiresAt = time.Now().Add(24 * time.Hour)
		if err := manager.Set(sessionToken, originalPayload); err != nil {
			t.Fatalf("set original session payload inside renewal window: %v", err)
		}

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/sessions/", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("renew session status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}

		var renewBody struct {
			Token          string    `json:"token"`
			ExpiresAt      time.Time `json:"expiresAt"`
			RenewableAfter time.Time `json:"renewableAfter"`
			Renewed        bool      `json:"renewed"`
		}
		decodeJSONBody(t, resp, &renewBody)
		if renewBody.Token == "" {
			t.Fatal("expected renewed token")
		}
		if renewBody.RenewableAfter.IsZero() {
			t.Fatal("expected renewed session response to include renewableAfter")
		}
		if !renewBody.Renewed {
			t.Fatal("expected renewed=true for session renewal")
		}
		if !renewBody.ExpiresAt.After(originalPayload.ExpiresAt) {
			t.Fatalf("expected renewed expiry after original expiry, got original=%v renewed=%v", originalPayload.ExpiresAt, renewBody.ExpiresAt)
		}
		if !renewBody.RenewableAfter.Before(renewBody.ExpiresAt) {
			t.Fatalf("expected renewed renewableAfter before expiresAt, got renewableAfter=%v expiresAt=%v", renewBody.RenewableAfter, renewBody.ExpiresAt)
		}

		renewedPayload, err := manager.Get(renewBody.Token)
		if err != nil {
			t.Fatalf("get renewed session payload: %v", err)
		}
		if renewedPayload.GetSID() != originalPayload.GetSID() {
			t.Fatalf("expected renewed session sid %s, got %s", originalPayload.GetSID(), renewedPayload.GetSID())
		}
		if renewedPayload.GetTID() == originalPayload.GetTID() {
			t.Fatalf("expected renewed session tid to rotate from %s", originalPayload.GetTID())
		}
		if !renewedPayload.ExpiresAt.After(originalPayload.ExpiresAt) {
			t.Fatalf("expected renewed payload expiry after original expiry, got original=%v renewed=%v", originalPayload.ExpiresAt, renewedPayload.ExpiresAt)
		}

		if _, err := manager.Get(sessionToken); err == nil {
			t.Fatal("expected original session token to be invalid after renewal")
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/logs/current", nil, bearerHeaders(renewBody.Token))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get renewed current signin log status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var currentLogBody struct {
			ExpiresAt *time.Time `json:"expiresAt"`
		}
		decodeJSONBody(t, resp, &currentLogBody)
		if currentLogBody.ExpiresAt == nil {
			t.Fatal("expected current signin log to include expiresAt")
		}
		if currentLogBody.ExpiresAt.Unix() != renewedPayload.ExpiresAt.Unix() {
			t.Fatalf("expected signin log expiry unix %d, got %d", renewedPayload.ExpiresAt.Unix(), currentLogBody.ExpiresAt.Unix())
		}
	})

	t.Run("users create list and get work for admin", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/", map[string]any{
			"username": "featureuser",
			"password": "test-password-123",
			"emails": []map[string]any{{
				"email":    "feature@example.com",
				"verified": true,
			}},
		}, adminHeaders())
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create user status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		location := resp.Header.Get("Location")
		resp.Body.Close()
		if location == "" {
			t.Fatalf("expected create user location header")
		}
		userID := parseResourceIDFromLocation(t, location)

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/?page=1&size=10&all=true", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list users status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		var listBody struct {
			Data []struct {
				ID        string   `json:"id"`
				Usernames []string `json:"usernames"`
				Emails    []string `json:"emails"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &listBody)
		found := false
		for _, user := range listBody.Data {
			if user.ID == userID {
				found = true
				if len(user.Usernames) != 1 || user.Usernames[0] != "featureuser" {
					t.Fatalf("unexpected usernames for created user: %#v", user)
				}
				if len(user.Emails) != 1 || user.Emails[0] != "feature@example.com" {
					t.Fatalf("unexpected emails for created user: %#v", user)
				}
			}
		}
		if !found {
			t.Fatalf("created user %q not present in list response: %#v", userID, listBody.Data)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get user status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var userBody struct {
			ID        string   `json:"id"`
			Usernames []string `json:"usernames"`
			Emails    []string `json:"emails"`
		}
		decodeJSONBody(t, resp, &userBody)
		if userBody.ID != userID || len(userBody.Usernames) != 1 || userBody.Usernames[0] != "featureuser" {
			t.Fatalf("unexpected get user body: %#v", userBody)
		}
	})

	t.Run("permissions create list and delete work for admin", func(t *testing.T) {
		publicScope := "feature.public." + strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", ""))
		privateScope := "feature.private." + strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", ""))

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/permissions/", map[string]any{
			"scope":    publicScope,
			"isPublic": true,
		}, adminHeaders())
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create public permission status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/permissions/", map[string]any{
			"scope":    privateScope,
			"isPublic": false,
		}, adminHeaders())
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create private permission status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/permissions/?page=1&size=20", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list public permissions status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		var publicList struct {
			Data []struct {
				ID    string `json:"id"`
				Scope string `json:"scope"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &publicList)
		privateSeen := false
		publicSeen := false
		for _, perm := range publicList.Data {
			if perm.Scope == publicScope {
				publicSeen = true
			}
			if perm.Scope == privateScope {
				privateSeen = true
			}
		}
		if !publicSeen || privateSeen {
			t.Fatalf("unexpected default permission list: %#v", publicList.Data)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/permissions/?page=1&size=20&all=true", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list all permissions status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		var allList struct {
			Data []struct {
				ID    string `json:"id"`
				Scope string `json:"scope"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &allList)

		privateID := ""
		publicSeen = false
		privateSeen = false
		for _, perm := range allList.Data {
			if perm.Scope == publicScope {
				publicSeen = true
			}
			if perm.Scope == privateScope {
				privateSeen = true
				privateID = perm.ID
			}
		}
		if !publicSeen || !privateSeen || privateID == "" {
			t.Fatalf("unexpected all permissions list: %#v", allList.Data)
		}

		resp = mustJSONRequest(t, env.server, http.MethodDelete, "/v2/permissions/?id="+url.QueryEscape(privateID), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("delete permission status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/permissions/?page=1&size=20&all=true", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list all permissions after delete status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		decodeJSONBody(t, resp, &allList)
		for _, perm := range allList.Data {
			if perm.ID == privateID {
				t.Fatalf("deleted permission still present: %#v", allList.Data)
			}
		}
	})

	t.Run("oauth2 auth redirect sends users to configured frontend", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, false)
		scope := "feature.redirect." + strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", ""))
		seedPermission(t, env, scope)

		path := fmt.Sprintf(
			"/v2/oauth2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=state123&prompt=login&nonce=nonce123",
			client.clientID.String(),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(scope),
		)
		resp := mustJSONRequest(t, env.server, http.MethodGet, path, nil, nil)
		if resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("auth redirect status = %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
		}
		resp.Body.Close()

		location := resp.Header.Get("Location")
		if location == "" {
			t.Fatalf("expected Location header")
		}

		redirectURL, err := url.Parse(location)
		if err != nil {
			t.Fatalf("Parse(Location): %v", err)
		}
		if redirectURL.Scheme != "https" || redirectURL.Host != "accounts.example.com" || redirectURL.Path != "/auth" {
			t.Fatalf("unexpected redirect target: %q", location)
		}

		query := redirectURL.Query()
		if query.Get("client_id") != client.clientID.String() ||
			query.Get("redirect_uri") != client.redirectURI ||
			query.Get("scope") != scope ||
			query.Get("state") != "state123" ||
			query.Get("prompt") != "login" ||
			query.Get("nonce") != "nonce123" {
			t.Fatalf("unexpected redirect query: %#v", query)
		}
	})

	t.Run("oauth2 auth redirect accepts form-encoded post requests", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, false)
		scope := "feature.redirect.post." + strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", ""))
		seedPermission(t, env, scope)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/auth", url.Values{
			"client_id":             {client.clientID.String()},
			"redirect_uri":          {client.redirectURI},
			"response_type":         {"code"},
			"scope":                 {scope},
			"state":                 {"state-post"},
			"prompt":                {"login"},
			"nonce":                 {"nonce-post"},
			"login_hint":            {"user@example.com"},
			"code_challenge":        {"challenge123"},
			"code_challenge_method": {"S256"},
		}, nil)
		if resp.StatusCode != http.StatusTemporaryRedirect {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("auth redirect POST status = %d, want %d, body=%s", resp.StatusCode, http.StatusTemporaryRedirect, string(raw))
		}
		resp.Body.Close()

		location := resp.Header.Get("Location")
		if location == "" {
			t.Fatalf("expected Location header")
		}

		redirectURL, err := url.Parse(location)
		if err != nil {
			t.Fatalf("Parse(Location): %v", err)
		}
		if redirectURL.Scheme != "https" || redirectURL.Host != "accounts.example.com" || redirectURL.Path != "/auth" {
			t.Fatalf("unexpected redirect target: %q", location)
		}

		query := redirectURL.Query()
		if query.Get("client_id") != client.clientID.String() ||
			query.Get("redirect_uri") != client.redirectURI ||
			query.Get("scope") != scope ||
			query.Get("state") != "state-post" ||
			query.Get("prompt") != "login" ||
			query.Get("nonce") != "nonce-post" ||
			query.Get("login_hint") != "user@example.com" ||
			query.Get("code_challenge") != "challenge123" ||
			query.Get("code_challenge_method") != "S256" {
			t.Fatalf("unexpected redirect query: %#v", query)
		}
	})

	t.Run("openid discovery advertises public client auth method", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("openid configuration status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}

		var body struct {
			TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		}
		decodeJSONBody(t, resp, &body)

		hasNone := false
		for _, method := range body.TokenEndpointAuthMethodsSupported {
			if method == "none" {
				hasNone = true
				break
			}
		}
		if !hasNone {
			t.Fatalf("expected token_endpoint_auth_methods_supported to include none, got %#v", body.TokenEndpointAuthMethodsSupported)
		}
	})

	t.Run("oauth2 client credentials exchange issues a real access token", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope := "feature.token." + strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", ""))
		permissionID := seedPermission(t, env, scope)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"grant_type":    {"client_credentials"},
			"scope":         {scope},
			"audience":      {"https://api.example.com https://secondary.example.com"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("token exchange status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}

		var tokenBody struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Scope       string `json:"scope"`
		}
		decodeJSONBody(t, resp, &tokenBody)
		if tokenBody.AccessToken == "" || tokenBody.TokenType != "Bearer" || tokenBody.Scope != scope || tokenBody.ExpiresIn <= 0 {
			t.Fatalf("unexpected token response: %#v", tokenBody)
		}

		payload, err := env.app.TokenServices().AccessToken().Get(tokenBody.AccessToken)
		if err != nil {
			t.Fatalf("TokenServices().AccessToken().Get: %v", err)
		}
		if payload.ClientID != client.clientID.String() {
			t.Fatalf("payload.ClientID = %q, want %q", payload.ClientID, client.clientID.String())
		}
		if payload.GrantType != "client_credentials" {
			t.Fatalf("payload.GrantType = %q", payload.GrantType)
		}
		if len(payload.Permissions) != 1 || payload.Permissions[0] != permissionID.String() {
			t.Fatalf("payload.Permissions = %#v, want [%q]", payload.Permissions, permissionID.String())
		}
		if len(payload.Audience) != 2 {
			t.Fatalf("payload.Audience = %#v", payload.Audience)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?access_token="+url.QueryEscape(tokenBody.AccessToken), nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("tokeninfo status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var tokenInfoBody struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			Scope       string `json:"scope"`
		}
		decodeJSONBody(t, resp, &tokenInfoBody)
		if tokenInfoBody.AccessToken != tokenBody.AccessToken || tokenInfoBody.TokenType != "Bearer" || tokenInfoBody.Scope != scope {
			t.Fatalf("unexpected tokeninfo response: %#v", tokenInfoBody)
		}

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/tokeninfo", url.Values{
			"access_token": {tokenBody.AccessToken},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("tokeninfo POST status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var tokenInfoPostBody struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			Scope       string `json:"scope"`
		}
		decodeJSONBody(t, resp, &tokenInfoPostBody)
		if tokenInfoPostBody.AccessToken != tokenBody.AccessToken || tokenInfoPostBody.TokenType != "Bearer" || tokenInfoPostBody.Scope != scope {
			t.Fatalf("unexpected tokeninfo POST response: %#v", tokenInfoPostBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", map[string]any{
			"client_id":     client.clientID.String(),
			"client_secret": "wrong-secret",
			"grant_type":    "client_credentials",
			"scope":         scope,
			"audience":      "https://api.example.com",
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("invalid secret status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if !strings.Contains(fmt.Sprint(errBody["error_description"]), "client_secret is invalid") {
			t.Fatalf("unexpected invalid secret response: %#v", errBody)
		}
	})

	t.Run("oauth2 clients jwks and client lifecycle routes work", func(t *testing.T) {
		userResp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/", map[string]any{
			"username": "clientowner",
			"password": "test-password-456",
			"emails": []map[string]any{{
				"email":    "clientowner@example.com",
				"verified": true,
			}},
		}, adminHeaders())
		if userResp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(userResp.Body)
			userResp.Body.Close()
			t.Fatalf("create owner user status = %d, want %d, body=%s", userResp.StatusCode, http.StatusCreated, string(raw))
		}
		ownerID := parseResourceIDFromLocation(t, userResp.Header.Get("Location"))
		userResp.Body.Close()

		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/jwks", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("jwks status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var jwksBody struct {
			Keys []struct {
				KeyID string `json:"kid"`
				Use   string `json:"use"`
			} `json:"keys"`
		}
		decodeJSONBody(t, resp, &jwksBody)
		if len(jwksBody.Keys) == 0 || jwksBody.Keys[0].KeyID == "" || jwksBody.Keys[0].Use != "sig" {
			t.Fatalf("unexpected JWKS response: %#v", jwksBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/apps/?user_id="+url.QueryEscape(ownerID), map[string]any{
			"name":         "Admin Created Client",
			"redirectURIs": []string{"https://client.example.com/callback"},
			"privacy":      "https://client.example.com/privacy",
			"terms":        "https://client.example.com/terms",
		}, adminHeaders())
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create oauth2 client status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		var createdClient struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			OwnerID string `json:"ownerId"`
		}
		decodeJSONBody(t, resp, &createdClient)
		if createdClient.ID == "" || createdClient.Name != "Admin Created Client" || createdClient.OwnerID != ownerID {
			t.Fatalf("unexpected created client response: %#v", createdClient)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/apps/?page=1&size=20&all=true", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("list oauth2 clients status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var listClients struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &listClients)
		found := false
		for _, client := range listClients.Data {
			if client.ID == createdClient.ID && client.Name == "Admin Created Client" {
				found = true
			}
		}
		if !found {
			t.Fatalf("created client not found in list: %#v", listClients.Data)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/apps/?page=1&size=20&all=true", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("list oauth2 clients with size status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var sizedClients struct {
			Pagination struct {
				Page int `json:"page"`
				Size int `json:"size"`
			} `json:"pagination"`
		}
		decodeJSONBody(t, resp, &sizedClients)
		if sizedClients.Pagination.Page != 1 || sizedClients.Pagination.Size != 20 {
			t.Fatalf("pagination = %#v, want page=1 size=20", sizedClients.Pagination)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/apps/"+createdClient.ID+"/", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get oauth2 client status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var getClient struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		decodeJSONBody(t, resp, &getClient)
		if getClient.ID != createdClient.ID || getClient.Name != "Admin Created Client" {
			t.Fatalf("unexpected get client response: %#v", getClient)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPut, "/v2/apps/"+createdClient.ID+"/", map[string]any{
			"name": "Renamed Client",
		}, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("update oauth2 client status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/apps/"+createdClient.ID+"/", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get updated oauth2 client status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &getClient)
		if getClient.Name != "Renamed Client" {
			t.Fatalf("client name not updated: %#v", getClient)
		}

		resp = mustJSONRequest(t, env.server, http.MethodDelete, "/v2/apps/"+createdClient.ID+"/", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("delete oauth2 client status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/apps/"+createdClient.ID+"/", nil, adminHeaders())
		if resp.StatusCode != http.StatusNotFound {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("deleted oauth2 client fetch status = %d, want %d, body=%s", resp.StatusCode, http.StatusNotFound, string(raw))
		}
	})

	t.Run("auth signup creates users and signout clears session users", func(t *testing.T) {
		username := "signup" + uniqueSuffix()
		email := username + "@example.com"
		password := "signup-password-123"

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signup", map[string]any{
			"email":    email,
			"username": username,
			"password": password,
			"name":     "Signup Feature User",
		}, map[string]string{
			"Origin": "https://accounts.example.com",
		})
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signup status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/?page=1&size=50&all=true&search="+url.QueryEscape(email), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("list users after signup status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var listBody struct {
			Data []struct {
				ID        string   `json:"id"`
				Usernames []string `json:"usernames"`
				Emails    []string `json:"emails"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &listBody)

		signedUpUserID := ""
		for _, user := range listBody.Data {
			if len(user.Emails) == 1 && user.Emails[0] == email {
				signedUpUserID = user.ID
				if len(user.Usernames) != 1 || user.Usernames[0] != username {
					t.Fatalf("unexpected usernames for signed-up user: %#v", user)
				}
			}
		}
		if signedUpUserID == "" {
			t.Fatalf("signed-up user with email %q not found in list: %#v", email, listBody.Data)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+signedUpUserID+"/userdata", nil, adminHeaders())
		var signedUpData struct {
			Name string `json:"name"`
		}
		decodeJSONBody(t, resp, &signedUpData)
		if signedUpData.Name != "Signup Feature User" {
			t.Fatalf("signup name = %q, want it stored", signedUpData.Name)
		}

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, signedUpUserID)

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signout", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signout status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/debug/?token="+url.QueryEscape(sessionToken), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("session debug after signout status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var debugBody struct {
			Users []string `json:"users"`
		}
		decodeJSONBody(t, resp, &debugBody)
		if len(debugBody.Users) != 0 {
			t.Fatalf("expected signout to clear session users, got %#v", debugBody.Users)
		}
	})

	t.Run("user subresource and metadata routes work with real sessions", func(t *testing.T) {
		username := "subuser" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "feature-password-123", email)
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/usernames", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get usernames status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var usernames []string
		decodeJSONBody(t, resp, &usernames)
		if len(usernames) != 1 || usernames[0] != username {
			t.Fatalf("unexpected initial usernames: %#v", usernames)
		}

		addedUsername := "alt" + uniqueSuffix()
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/"+userID+"/usernames", map[string]any{
			"username": addedUsername,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("add username status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/usernames", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get usernames after add status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &usernames)
		if !strings.Contains(strings.Join(usernames, ","), addedUsername) {
			t.Fatalf("expected added username in response: %#v", usernames)
		}

		renamedUsername := "renamed" + uniqueSuffix()
		resp = mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/usernames", map[string]any{
			"username": renamedUsername,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("change username status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/usernames", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get usernames after change status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &usernames)
		if len(usernames) != 1 || usernames[0] != renamedUsername {
			t.Fatalf("unexpected usernames after change: %#v", usernames)
		}

		resp = mustJSONRequest(t, env.server, http.MethodDelete, "/v2/users/"+userID+"/usernames?username="+url.QueryEscape(renamedUsername), nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("remove username status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/usernames", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get usernames after delete status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &usernames)
		if len(usernames) != 0 {
			t.Fatalf("expected usernames to be empty after delete, got %#v", usernames)
		}

		addedEmail := "extra+" + uniqueSuffix() + "@example.com"
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/"+userID+"/emails", map[string]any{
			"email":    addedEmail,
			"verified": false,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("add email status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		resp.Body.Close()

		// A non-admin session cannot mark its own email verified; only an admin
		// can. The self-service attempt must be rejected.
		resp = mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/emails?email="+url.QueryEscape(addedEmail), map[string]any{
			"verified": true,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusForbidden {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("self-verify email status = %d, want %d, body=%s", resp.StatusCode, http.StatusForbidden, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/emails", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get emails status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var emails []struct {
			Email    string `json:"email"`
			Verified bool   `json:"verified"`
		}
		decodeJSONBody(t, resp, &emails)
		foundEmail := false
		for _, item := range emails {
			if item.Email == addedEmail {
				foundEmail = true
				if item.Verified {
					t.Fatalf("expected added email to remain unverified after rejected self-verify: %#v", emails)
				}
			}
		}
		if !foundEmail {
			t.Fatalf("expected added email in response: %#v", emails)
		}

		resp = mustJSONRequest(t, env.server, http.MethodDelete, "/v2/users/"+userID+"/emails?email="+url.QueryEscape(addedEmail), nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("remove email status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/emails", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get emails after delete status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &emails)
		for _, item := range emails {
			if item.Email == addedEmail {
				t.Fatalf("removed email still present: %#v", emails)
			}
		}

		addedPhone := "+14155550123"
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/"+userID+"/phones", map[string]any{
			"phone":    addedPhone,
			"verified": false,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("add phone status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		resp.Body.Close()

		// As with email, a non-admin session cannot mark its own phone
		// verified; the self-service attempt must be rejected.
		resp = mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/phones?phone="+url.QueryEscape(addedPhone), map[string]any{
			"verified": true,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusForbidden {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("self-verify phone status = %d, want %d, body=%s", resp.StatusCode, http.StatusForbidden, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/phones", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get phones status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var phones []struct {
			Phone    string `json:"phone"`
			Verified bool   `json:"verified"`
		}
		decodeJSONBody(t, resp, &phones)
		foundPhone := false
		for _, item := range phones {
			if item.Phone == addedPhone {
				foundPhone = true
				if item.Verified {
					t.Fatalf("expected phone to remain unverified after rejected self-verify: %#v", phones)
				}
			}
		}
		if !foundPhone {
			t.Fatalf("expected added phone in response: %#v", phones)
		}

		resp = mustJSONRequest(t, env.server, http.MethodDelete, "/v2/users/"+userID+"/phones?phone="+url.QueryEscape(addedPhone), nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("remove phone status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/phones", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get phones after delete status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &phones)
		for _, item := range phones {
			if item.Phone != "" {
				t.Fatalf("expected no phones after delete, got %#v", phones)
			}
		}

		resp = mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/password", map[string]any{
			"prevPassword": "feature-password-123",
			"newPassword":  "rotated-password-123",
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("change password status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		var passwordUser database.User
		if err := env.db.Preload("Authenticators").First(&passwordUser, "id = ?", userID).Error; err != nil {
			t.Fatalf("load user after password change: %v", err)
		}
		if !passwordUser.CheckPassword("rotated-password-123") || passwordUser.CheckPassword("feature-password-123") {
			t.Fatalf("password change did not persist")
		}

		resp = mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/userdata", map[string]any{
			"name":        "Feature User",
			"displayName": "Feature Display",
			"language":    "en",
			"timezone":    "UTC",
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("update user data status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/userdata", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get user data status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var userData struct {
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
			Language    string `json:"language"`
			Timezone    string `json:"timezone"`
		}
		decodeJSONBody(t, resp, &userData)
		if userData.Name != "Feature User" || userData.DisplayName != "Feature Display" || userData.Language != "en" || userData.Timezone != "UTC" {
			t.Fatalf("unexpected user data response: %#v", userData)
		}

		var persistedUserData database.UserData
		if err := env.db.First(&persistedUserData, "user_id = ?", userID).Error; err != nil {
			t.Fatalf("load persisted user data: %v", err)
		}
		if persistedUserData.Name != "Feature User" || persistedUserData.DisplayName != "Feature Display" {
			t.Fatalf("unexpected persisted user data: %#v", persistedUserData)
		}
		if persistedUserData.Language == nil || *persistedUserData.Language != "en" || persistedUserData.Timezone == nil || *persistedUserData.Timezone != "UTC" {
			t.Fatalf("unexpected persisted locale data: %#v", persistedUserData)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/userdata", map[string]any{
			"language": nil,
			"timezone": nil,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("clear locale data status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/userdata", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get cleared user data status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var clearedUserData map[string]any
		decodeJSONBody(t, resp, &clearedUserData)
		if _, ok := clearedUserData["language"]; ok {
			t.Fatalf("expected cleared language to be omitted, got %#v", clearedUserData)
		}
		if _, ok := clearedUserData["timezone"]; ok {
			t.Fatalf("expected cleared timezone to be omitted, got %#v", clearedUserData)
		}

		var clearedPersistedUserData database.UserData
		if err := env.db.First(&clearedPersistedUserData, "user_id = ?", userID).Error; err != nil {
			t.Fatalf("load persisted user data after locale clear: %v", err)
		}
		if clearedPersistedUserData.Language != nil || clearedPersistedUserData.Timezone != nil {
			t.Fatalf("expected persisted locale data to be null, got %#v", clearedPersistedUserData)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/metadata/", map[string]any{
			"tier": "beta",
			"nested": map[string]any{
				"one": float64(1),
			},
		}, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("update metadata status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPatch, "/v2/users/"+userID+"/metadata/", map[string]any{
			"flag": true,
			"nested": map[string]any{
				"two": float64(2),
			},
		}, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("merge metadata status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/metadata/", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get metadata status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var metadata map[string]any
		decodeJSONBody(t, resp, &metadata)
		if metadata["tier"] != "beta" || metadata["flag"] != true {
			t.Fatalf("unexpected metadata response: %#v", metadata)
		}
		nested, ok := metadata["nested"].(map[string]any)
		if !ok || nested["one"] != float64(1) || nested["two"] != float64(2) {
			t.Fatalf("expected merged nested metadata, got %#v", metadata)
		}
	})

	t.Run("user access checks allow self and admin but deny cross-user access", func(t *testing.T) {
		aliceUsername := "alice" + uniqueSuffix()
		bobUsername := "bob" + uniqueSuffix()
		aliceID := mustCreateUser(t, env, aliceUsername, "alice-password-123", aliceUsername+"@example.com")
		bobID := mustCreateUser(t, env, bobUsername, "bob-password-123", bobUsername+"@example.com")

		aliceToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, aliceToken, aliceID)

		bobToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, bobToken, bobID)

		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+aliceID+"/", nil, bearerHeaders(aliceToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("self get user status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var selfBody struct {
			ID string `json:"id"`
		}
		decodeJSONBody(t, resp, &selfBody)
		if selfBody.ID != aliceID {
			t.Fatalf("self get user returned wrong id: %#v", selfBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+bobID+"/", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("admin get user status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var adminBody struct {
			ID string `json:"id"`
		}
		decodeJSONBody(t, resp, &adminBody)
		if adminBody.ID != bobID {
			t.Fatalf("admin get user returned wrong id: %#v", adminBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+aliceID+"/usernames", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("admin get usernames status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var adminUsernames []string
		decodeJSONBody(t, resp, &adminUsernames)
		if len(adminUsernames) != 1 || adminUsernames[0] != aliceUsername {
			t.Fatalf("unexpected admin usernames response: %#v", adminUsernames)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/?page=1&size=20", nil, bearerHeaders(aliceToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("self list users status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var listBody struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &listBody)
		if len(listBody.Data) != 1 || listBody.Data[0].ID != aliceID {
			t.Fatalf("non-admin list should only expose self, got %#v", listBody.Data)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+bobID+"/", nil, bearerHeaders(aliceToken))
		if resp.StatusCode != http.StatusUnauthorized {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("cross-user get status = %d, want %d, body=%s", resp.StatusCode, http.StatusUnauthorized, string(raw))
		}
		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if !strings.Contains(fmt.Sprint(errBody["message"]), "not allowed to access this user") {
			t.Fatalf("unexpected cross-user error body: %#v", errBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+aliceID+"/usernames", nil, bearerHeaders(bobToken))
		if resp.StatusCode != http.StatusUnauthorized {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("cross-user usernames status = %d, want %d, body=%s", resp.StatusCode, http.StatusUnauthorized, string(raw))
		}
		decodeJSONBody(t, resp, &errBody)
		if !strings.Contains(fmt.Sprint(errBody["message"]), "not allowed to access this user") {
			t.Fatalf("unexpected cross-user usernames error body: %#v", errBody)
		}
	})

	t.Run("oauth2 client secrets and redirect uri routes work", func(t *testing.T) {
		ownerUsername := "owner" + uniqueSuffix()
		ownerID := mustCreateUser(t, env, ownerUsername, "owner-password-123", ownerUsername+"@example.com")

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/apps/?user_id="+url.QueryEscape(ownerID), map[string]any{
			"name":         "Managed Client",
			"redirectURIs": []string{"https://managed.example.com/callback"},
			"privacy":      "https://managed.example.com/privacy",
			"terms":        "https://managed.example.com/terms",
		}, adminHeaders())
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create managed client status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		var clientBody struct {
			ID string `json:"id"`
		}
		decodeJSONBody(t, resp, &clientBody)
		if clientBody.ID == "" {
			t.Fatalf("expected created client id")
		}

		baseSecretsPath := "/v2/apps/" + clientBody.ID + "/oauth2/secrets/?user_id=" + url.QueryEscape(ownerID)
		resp = mustJSONRequest(t, env.server, http.MethodGet, baseSecretsPath, nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get initial client secrets status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var secrets []struct {
			ID           string `json:"id"`
			ClientSecret string `json:"client_secret"`
			Notes        string `json:"notes"`
		}
		decodeJSONBody(t, resp, &secrets)
		if len(secrets) != 0 {
			t.Fatalf("expected no initial secrets, got %#v", secrets)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, baseSecretsPath, map[string]any{
			"notes": "primary feature secret",
		}, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create client secret status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var createdSecret struct {
			ID           string `json:"id"`
			ClientSecret string `json:"client_secret"`
			Notes        string `json:"notes"`
		}
		decodeJSONBody(t, resp, &createdSecret)
		if createdSecret.ID == "" || createdSecret.ClientSecret == "" || createdSecret.Notes != "primary feature secret" {
			t.Fatalf("unexpected created secret response: %#v", createdSecret)
		}
		if len(createdSecret.ClientSecret) != 64 {
			t.Fatalf("created client secret length = %d, want 64", len(createdSecret.ClientSecret))
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, baseSecretsPath, nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get client secrets after create status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &secrets)
		if len(secrets) != 1 || secrets[0].ID != createdSecret.ID {
			t.Fatalf("unexpected secrets list after create: %#v", secrets)
		}

		resp = mustJSONRequest(t, env.server, http.MethodDelete, baseSecretsPath+"&secret_id="+url.QueryEscape(createdSecret.ID), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("delete client secret status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, baseSecretsPath, nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get client secrets after delete status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &secrets)
		if len(secrets) != 0 {
			t.Fatalf("expected secrets to be empty after delete, got %#v", secrets)
		}

		baseRedirectsPath := "/v2/apps/" + clientBody.ID + "/oauth2/redirect_uris/?user_id=" + url.QueryEscape(ownerID)
		resp = mustJSONRequest(t, env.server, http.MethodGet, baseRedirectsPath, nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get redirect uris status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var redirectURIs []struct {
			ID          string `json:"id"`
			RedirectURI string `json:"redirect_uri"`
		}
		decodeJSONBody(t, resp, &redirectURIs)
		if len(redirectURIs) != 1 {
			t.Fatalf("expected one initial redirect uri, got %#v", redirectURIs)
		}

		newRedirectURI := "https://managed.example.com/callback/" + uniqueSuffix()
		resp = mustJSONRequest(t, env.server, http.MethodPost, baseRedirectsPath, map[string]any{
			"redirect_uri": newRedirectURI,
		}, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create redirect uri status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, baseRedirectsPath, nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get redirect uris after create status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &redirectURIs)
		redirectID := ""
		foundRedirect := false
		for _, item := range redirectURIs {
			if item.RedirectURI == newRedirectURI {
				foundRedirect = true
				redirectID = item.ID
			}
		}
		if !foundRedirect || redirectID == "" {
			t.Fatalf("expected created redirect uri in response: %#v", redirectURIs)
		}

		resp = mustJSONRequest(t, env.server, http.MethodDelete, baseRedirectsPath+"&redirectUriId="+url.QueryEscape(redirectID), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("delete redirect uri status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, baseRedirectsPath, nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get redirect uris after delete status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &redirectURIs)
		for _, item := range redirectURIs {
			if item.ID == redirectID {
				t.Fatalf("deleted redirect uri still present: %#v", redirectURIs)
			}
		}
	})

	t.Run("oauth2 client secret length follows config", func(t *testing.T) {
		prevLength := env.app.Config().OAuth2Config.ClientSecretLength
		env.app.Config().OAuth2Config.ClientSecretLength = 96
		t.Cleanup(func() {
			env.app.Config().OAuth2Config.ClientSecretLength = prevLength
		})

		ownerUsername := "customowner" + uniqueSuffix()
		ownerID := mustCreateUser(t, env, ownerUsername, "owner-password-123", ownerUsername+"@example.com")

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/apps/?user_id="+url.QueryEscape(ownerID), map[string]any{
			"name":         "Managed Client",
			"redirectURIs": []string{"https://managed.example.com/callback"},
			"privacy":      "https://managed.example.com/privacy",
			"terms":        "https://managed.example.com/terms",
		}, adminHeaders())
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create managed client status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
		}
		var clientBody struct {
			ID string `json:"id"`
		}
		decodeJSONBody(t, resp, &clientBody)

		baseSecretsPath := "/v2/apps/" + clientBody.ID + "/oauth2/secrets/?user_id=" + url.QueryEscape(ownerID)
		resp = mustJSONRequest(t, env.server, http.MethodPost, baseSecretsPath, map[string]any{
			"notes": "custom length secret",
		}, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create client secret status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var createdSecret struct {
			ClientSecret string `json:"client_secret"`
		}
		decodeJSONBody(t, resp, &createdSecret)
		if len(createdSecret.ClientSecret) != 96 {
			t.Fatalf("created client secret length = %d, want 96", len(createdSecret.ClientSecret))
		}
	})

	t.Run("oauth2 consent auth code refresh and unauthorize routes work", func(t *testing.T) {
		username := "consent" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "consent-password-123", email)
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")
		ensurePermissionScope(t, env, "profile")
		ensurePermissionScope(t, env, "email")

		authQuery := fmt.Sprintf("/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s",
			client.clientID.String(),
			url.QueryEscape("openid profile email"),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(userID),
		)

		resp := mustJSONRequest(t, env.server, http.MethodGet, authQuery, nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("auth endpoint call status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var consentBody struct {
			UserConsentRequired bool `json:"userConsentRequired"`
		}
		decodeJSONBody(t, resp, &consentBody)
		if !consentBody.UserConsentRequired {
			t.Fatalf("expected initial consent to be required")
		}

		authorizeQuery := authQuery + "&access_type=offline&state=state-123&nonce=nonce-123&approve=true"
		resp = mustJSONRequest(t, env.server, http.MethodPost, authorizeQuery, nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("authorize client status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var authorizeBody struct {
			Code   string `json:"code"`
			Tokens any    `json:"tokens"`
		}
		decodeJSONBody(t, resp, &authorizeBody)
		if authorizeBody.Code == "" || authorizeBody.Tokens != nil {
			t.Fatalf("unexpected authorize response: %#v", authorizeBody)
		}

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"code":          {authorizeBody.Code},
			"grant_type":    {"authorization_code"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("authorization code exchange status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var tokenBody struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			IdToken      string `json:"id_token"`
			TokenType    string `json:"token_type"`
		}
		decodeJSONBody(t, resp, &tokenBody)
		if tokenBody.AccessToken == "" || tokenBody.RefreshToken == "" || tokenBody.IdToken == "" || tokenBody.TokenType != "Bearer" {
			t.Fatalf("unexpected authorization code token response: %#v", tokenBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/userinfo", nil, map[string]string{
			"Authorization": "Bearer " + tokenBody.AccessToken,
		})
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("userinfo status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var userInfo map[string]any
		decodeJSONBody(t, resp, &userInfo)
		if userInfo["sub"] != userID || userInfo["preferred_username"] != username {
			t.Fatalf("unexpected userinfo response: %#v", userInfo)
		}

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/userinfo", url.Values{
			"access_token": {tokenBody.AccessToken},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("userinfo POST status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var userInfoPost map[string]any
		decodeJSONBody(t, resp, &userInfoPost)
		if userInfoPost["sub"] != userID || userInfoPost["preferred_username"] != username {
			t.Fatalf("unexpected userinfo POST response: %#v", userInfoPost)
		}

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {tokenBody.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("refresh token exchange status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var refreshBody struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}
		decodeJSONBody(t, resp, &refreshBody)
		if refreshBody.AccessToken == "" || refreshBody.TokenType != "Bearer" {
			t.Fatalf("unexpected refresh token response: %#v", refreshBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/apps/?page=1&size=20&authorized=true&user_id="+url.QueryEscape(userID), nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("authorized clients list status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var authorizedClients struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &authorizedClients)
		foundAuthorized := false
		for _, item := range authorizedClients.Data {
			if item.ID == client.clientID.String() {
				foundAuthorized = true
			}
		}
		if !foundAuthorized {
			t.Fatalf("authorized client not found in list: %#v", authorizedClients.Data)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/apps/"+client.clientID.String()+"/unauthorize?user_id="+url.QueryEscape(userID), nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("unauthorize client status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, authQuery, nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("auth endpoint call after unauthorize status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		decodeJSONBody(t, resp, &consentBody)
		if !consentBody.UserConsentRequired {
			t.Fatalf("expected consent to be required again after unauthorize")
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/userinfo", nil, map[string]string{
			"Authorization": "Bearer " + tokenBody.AccessToken,
		})
		if resp.StatusCode == http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("userinfo after unauthorize should fail, got status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("get user data creates missing user data record", func(t *testing.T) {
		username := "getuserdata" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "userdata-password-123", email)
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/userdata", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get user data status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}

		var userData map[string]any
		decodeJSONBody(t, resp, &userData)
		if len(userData) != 0 {
			t.Fatalf("expected empty user data response, got %#v", userData)
		}

		var persistedUserData database.UserData
		if err := env.db.First(&persistedUserData, "user_id = ?", userID).Error; err != nil {
			t.Fatalf("load persisted user data after get: %v", err)
		}
	})

	t.Run("signin flow issues challenge token and completes with password", func(t *testing.T) {
		username := "signin" + uniqueSuffix()
		email := username + "@example.com"
		password := "signin-password-123"
		userID := mustCreateUser(t, env, username, password, email)
		sessionToken := mustCreateSessionToken(t, env)

		// Step 1: POST /v2/auth/signin with username → get challenge token
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var signinBody struct {
			Action       string `json:"action"`
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)
		if signinBody.Action != "challenge" || signinBody.RequestToken == "" {
			t.Fatalf("expected challenge action with token, got %#v", signinBody)
		}
		challengeToken := signinBody.RequestToken

		// Step 2: GET /v2/auth/challenge → list available challenge types
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/auth/challenge?token="+url.QueryEscape(challengeToken)+"&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get challenge types status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var challengeTypes []string
		decodeJSONBody(t, resp, &challengeTypes)
		foundPassword := false
		for _, ct := range challengeTypes {
			if ct == "password" {
				foundPassword = true
			}
		}
		if !foundPassword {
			t.Fatalf("expected password in challenge types, got %#v", challengeTypes)
		}

		// Step 3: POST /v2/auth/challenge/issue → issue password challenge
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue challenge status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Step 4: POST /v2/auth/challenge/validate → validate password
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate challenge status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var validateBody struct {
			Passed bool `json:"passed"`
		}
		decodeJSONBody(t, resp, &validateBody)
		if !validateBody.Passed {
			t.Fatalf("expected challenge to pass")
		}

		// Step 5: POST /v2/auth/signin with challengeToken → complete sign-in
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       username,
			"challengeToken": challengeToken,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin complete status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Verify user is now in the session
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/debug/?token="+url.QueryEscape(sessionToken), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("session debug status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var debugBody struct {
			Users []string `json:"users"`
		}
		decodeJSONBody(t, resp, &debugBody)
		found := false
		for _, u := range debugBody.Users {
			if u == userID {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected user %q in session users, got %#v", userID, debugBody.Users)
		}
	})

	t.Run("signin with invalid username returns not found", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": "nonexistent" + uniqueSuffix(),
		}, nil)
		if resp.StatusCode != http.StatusNotFound {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin unknown user status = %d, want %d, body=%s", resp.StatusCode, http.StatusNotFound, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("signin with wrong password fails challenge validation", func(t *testing.T) {
		username := "wrongpw" + uniqueSuffix()
		email := username + "@example.com"
		mustCreateUser(t, env, username, "correct-password-123", email)

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)

		// Issue challenge
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue challenge status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Validate with wrong password
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", map[string]any{
			"response": "wrong-password",
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate wrong password status = %d, want %d, body=%s", resp.StatusCode, http.StatusUnauthorized, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("signin via email works as identifier", func(t *testing.T) {
		username := "emailsignin" + uniqueSuffix()
		email := username + "@example.com"
		password := "email-signin-pass-123"
		userID := mustCreateUser(t, env, username, password, email)
		sessionToken := mustCreateSessionToken(t, env)

		// Sign in using email address
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": email,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin by email status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)
		if signinBody.RequestToken == "" {
			t.Fatalf("expected challenge token for email-based signin")
		}

		// Complete the flow
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue challenge status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate challenge status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       email,
			"challengeToken": signinBody.RequestToken,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin complete status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/debug/?token="+url.QueryEscape(sessionToken), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("session debug status = %d", resp.StatusCode)
		}
		var debugBody struct {
			Users []string `json:"users"`
		}
		decodeJSONBody(t, resp, &debugBody)
		found := false
		for _, u := range debugBody.Users {
			if u == userID {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected user %q in session users after email signin, got %#v", userID, debugBody.Users)
		}
	})

	t.Run("admin credentials cannot sign users in", func(t *testing.T) {
		username := "adminbypass" + uniqueSuffix()
		mustCreateUser(t, env, username, "bypass-password-123", username+"@example.com")

		// An admin acts on users through the admin API; it has no session to
		// sign a user into, so it cannot skip a user's authenticators.
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, adminHeaders())
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("admin signin = %d, want %d, body=%s", resp.StatusCode, http.StatusForbidden, string(raw))
		}
	})

	t.Run("user update endpoint works and rejects 2fa without authenticator", func(t *testing.T) {
		username := "update2fa" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "update-password-123", email)
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		// Update with empty body succeeds (no-op)
		resp := mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/", map[string]any{}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("update user empty body status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Enabling 2FA without authenticator should fail
		resp = mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/", map[string]any{
			"twoFactorEnabled": true,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("enable 2fa without authenticator status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}
		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if !strings.Contains(fmt.Sprint(errBody["message"]), "two factor authenticator") {
			t.Fatalf("unexpected error message: %#v", errBody)
		}
	})

	t.Run("user delete soft deletes user", func(t *testing.T) {
		username := "todelete" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "delete-password-123", email)
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		// Delete user (soft delete)
		resp := mustJSONRequest(t, env.server, http.MethodDelete, "/v2/users/"+userID+"/", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("delete user status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Verify user is soft-deleted (deletedAt is set)
		var user database.User
		if err := env.db.First(&user, "id = ?", userID).Error; err != nil {
			t.Fatalf("load user after delete: %v", err)
		}
		if user.DeletedAt == nil {
			t.Fatalf("expected soft-deleted user to have DeletedAt set")
		}

		// Verify user is removed from session
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/debug/?token="+url.QueryEscape(sessionToken), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("session debug status = %d", resp.StatusCode)
		}
		var debugBody struct {
			Users []string `json:"users"`
		}
		decodeJSONBody(t, resp, &debugBody)
		for _, u := range debugBody.Users {
			if u == userID {
				t.Fatalf("expected deleted user to be removed from session")
			}
		}
	})

	t.Run("session validation prunes deleted users", func(t *testing.T) {
		username := "deletedsession" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "deleted-session-password-123", email)
		activeUserID := mustCreateUser(t, env, "activesession"+uniqueSuffix(), "active-session-password-123", "active"+uniqueSuffix()+"@example.com")
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)
		mustAttachUserToSession(t, env, sessionToken, activeUserID)

		now := time.Now()
		if err := env.db.Model(&database.User{}).Where("id = ?", userID).Update("deleted_at", &now).Error; err != nil {
			t.Fatalf("soft delete user directly: %v", err)
		}

		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate deleted-user session status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/debug/?token="+url.QueryEscape(sessionToken), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("admin debug deleted-user session status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}

		var debugBody struct {
			Users []string `json:"users"`
		}
		decodeJSONBody(t, resp, &debugBody)
		for _, u := range debugBody.Users {
			if u == userID {
				t.Fatalf("expected deleted user to be pruned from session")
			}
		}
		if len(debugBody.Users) != 1 || debugBody.Users[0] != activeUserID {
			t.Fatalf("expected only active user %q to remain, got %#v", activeUserID, debugBody.Users)
		}
	})

	t.Run("signin completion rejects user deleted after challenge issuance", func(t *testing.T) {
		username := "deletechallenge" + uniqueSuffix()
		password := "delete-challenge-password-123"
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, password, email)
		sessionToken := mustCreateSessionToken(t, env)
		headers := bearerHeaders(sessionToken)

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, headers)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}

		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)
		if signinBody.RequestToken == "" {
			t.Fatalf("expected challenge token for signin")
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate challenge status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		now := time.Now()
		if err := env.db.Model(&database.User{}).Where("id = ?", userID).Update("deleted_at", &now).Error; err != nil {
			t.Fatalf("soft delete user directly: %v", err)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       username,
			"challengeToken": signinBody.RequestToken,
		}, headers)
		if resp.StatusCode != http.StatusNotFound {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin complete deleted user status = %d, want %d, body=%s", resp.StatusCode, http.StatusNotFound, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("user signout removes specific user from session", func(t *testing.T) {
		username := "signoutuser" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "signout-password-123", email)
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		// Sign out specific user
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/"+userID+"/signout", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("user signout status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Verify user is removed from session
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/debug/?token="+url.QueryEscape(sessionToken), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("session debug status = %d", resp.StatusCode)
		}
		var debugBody struct {
			Users []string `json:"users"`
		}
		decodeJSONBody(t, resp, &debugBody)
		for _, u := range debugBody.Users {
			if u == userID {
				t.Fatalf("expected user %q to be removed from session after signout", userID)
			}
		}
	})

	t.Run("signin logs list and force signout work", func(t *testing.T) {
		username := "loguser" + uniqueSuffix()
		email := username + "@example.com"
		password := "log-password-123"
		userID := mustCreateUser(t, env, username, password, email)
		env.app.SetGeoIPResolver(func(ip string) (*database.GeoIPResult, error) {
			if ip == "" {
				return nil, nil
			}
			return &database.GeoIPResult{
				Country:     "Germany",
				CountryCode: "DE",
				Data: map[string]any{
					"country":     "Germany",
					"countryCode": "DE",
				},
			}, nil
		})
		sessionToken := mustCreateSessionToken(t, env)
		currentUserAgent := "SignInLogCurrent/1.0"
		mustCompletePasswordSignIn(t, env, sessionToken, username, password, map[string]string{
			"User-Agent": currentUserAgent,
		})

		// Create a second session with a log to test force signout against
		otherSession := mustCreateSessionToken(t, env)
		otherUserAgent := "SignInLogOther/1.0"
		mustCompletePasswordSignIn(t, env, otherSession, username, password, map[string]string{
			"User-Agent": otherUserAgent,
		})
		otherSessionPayload, err := env.app.TokenServices().Session().Get(otherSession)
		if err != nil {
			t.Fatalf("get other session payload: %v", err)
		}
		expiredSessionAt := time.Now().Add(-15 * time.Minute).UTC().Truncate(time.Second)
		otherSessionPayload.ExpiresAt = expiredSessionAt
		if err := env.app.TokenServices().Session().SetByTID(otherSessionPayload.GetTID(), otherSessionPayload); err != nil {
			t.Fatalf("expire other session payload: %v", err)
		}
		if err := api.UpdateSignInLogExpiry(&otherSessionPayload); err != nil {
			t.Fatalf("expire other session signin log: %v", err)
		}

		// GET /v2/users/{user_id}/logs
		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/logs?page=1&size=10", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get signin logs status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var logsBody struct {
			Data []struct {
				ID          string         `json:"id"`
				IP          string         `json:"ip"`
				Country     string         `json:"country"`
				CountryCode string         `json:"countryCode"`
				GeoIPData   map[string]any `json:"geoipData"`
				ExpiresAt   *time.Time     `json:"expiresAt"`
				SignedOutAt *time.Time     `json:"signedOutAt"`
				UserAgent   string         `json:"userAgent"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &logsBody)
		if len(logsBody.Data) < 2 {
			t.Fatalf("expected at least 2 signin log entries, got %d", len(logsBody.Data))
		}
		foundCurrent := false
		foundOther := false
		for _, log := range logsBody.Data {
			if log.UserAgent == currentUserAgent {
				foundCurrent = true
				if log.IP == "" {
					t.Fatalf("expected current session log to include request IP")
				}
				if log.Country == "" {
					t.Fatalf("expected current session log to include resolved country")
				}
				if log.CountryCode != "DE" {
					t.Fatalf("expected current session log to include country code DE, got %#v", log)
				}
				if fmt.Sprint(log.GeoIPData["countryCode"]) != "DE" {
					t.Fatalf("expected current session log to include geoip data, got %#v", log.GeoIPData)
				}
				if log.ExpiresAt == nil {
					t.Fatalf("expected current session log to include expiresAt")
				}
				if log.SignedOutAt != nil {
					t.Fatalf("expected current session log to stay active, got signedOutAt=%v", log.SignedOutAt)
				}
			}
			if log.UserAgent == otherUserAgent {
				foundOther = true
				if log.IP == "" {
					t.Fatalf("expected other session log to include request IP")
				}
				if log.Country == "" {
					t.Fatalf("expected other session log to include resolved country")
				}
				if log.CountryCode != "DE" {
					t.Fatalf("expected other session log to include country code DE, got %#v", log)
				}
				if fmt.Sprint(log.GeoIPData["countryCode"]) != "DE" {
					t.Fatalf("expected other session log to include geoip data, got %#v", log.GeoIPData)
				}
				if log.ExpiresAt == nil {
					t.Fatalf("expected expired session log to expose expiresAt")
				}
				if !log.ExpiresAt.Equal(expiredSessionAt) {
					t.Fatalf("expected expired session expiresAt %v, got %v", expiredSessionAt, log.ExpiresAt)
				}
				if log.SignedOutAt == nil {
					t.Fatalf("expected expired session log to expose signedOutAt")
				}
				if !log.SignedOutAt.Equal(expiredSessionAt) {
					t.Fatalf("expected expired session signedOutAt %v, got %v", expiredSessionAt, log.SignedOutAt)
				}
			}
		}
		if !foundCurrent || !foundOther {
			t.Fatalf("expected both signin log user agents, got %#v", logsBody.Data)
		}

		currentSessionPayload, err := env.app.TokenServices().Session().Get(sessionToken)
		if err != nil {
			t.Fatalf("get current session payload: %v", err)
		}

		oldLog := &database.SignInLog{
			SignInLogFields: models.SignInLogFields{
				ID:         uuid.New(),
				SessionID:  uuid.MustParse(currentSessionPayload.GetSID()),
				UserID:     uuid.MustParse(userID),
				SignedInAt: time.Now().Add(-45 * 24 * time.Hour),
				IP:         "203.0.113.10",
				Country:    "US",
				GeoIPData: map[string]any{
					"country":     "United States",
					"countryCode": "US",
				},
				UserAgent: "HistoricalLog/1.0",
			},
		}
		if err := env.db.Create(oldLog).Error; err != nil {
			t.Fatalf("create historical signin log: %v", err)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/logs/first", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get first signin log status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var firstLogBody struct {
			UserAgent   string `json:"userAgent"`
			CountryCode string `json:"countryCode"`
		}
		decodeJSONBody(t, resp, &firstLogBody)
		if firstLogBody.UserAgent != "HistoricalLog/1.0" || firstLogBody.CountryCode != "US" {
			t.Fatalf("expected first signin log to be historical session in US, got %#v", firstLogBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/logs/latest", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get latest signin log status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var latestLogBody struct {
			UserAgent   string `json:"userAgent"`
			CountryCode string `json:"countryCode"`
		}
		decodeJSONBody(t, resp, &latestLogBody)
		if latestLogBody.UserAgent != otherUserAgent || latestLogBody.CountryCode != "DE" {
			t.Fatalf("expected latest signin log to be other session in DE, got %#v", latestLogBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/logs/current", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get current signin log status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var currentLogBody struct {
			UserAgent   string `json:"userAgent"`
			CountryCode string `json:"countryCode"`
		}
		decodeJSONBody(t, resp, &currentLogBody)
		if currentLogBody.UserAgent != currentUserAgent || currentLogBody.CountryCode != "DE" {
			t.Fatalf("expected current signin log to match active session in DE, got %#v", currentLogBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/logs/statistics", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get signin log statistics status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var statisticsBody struct {
			Statistics struct {
				Countries []struct {
					Country     string `json:"country"`
					CountryCode string `json:"countryCode"`
					Count       int64  `json:"count"`
				} `json:"countries"`
			} `json:"statistics"`
		}
		decodeJSONBody(t, resp, &statisticsBody)
		if len(statisticsBody.Statistics.Countries) != 1 {
			t.Fatalf("expected one country in signin log statistics, got %#v", statisticsBody)
		}
		if statisticsBody.Statistics.Countries[0].CountryCode != "DE" || statisticsBody.Statistics.Countries[0].Count != 2 {
			t.Fatalf("expected DE signin statistics count 2, got %#v", statisticsBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/logs/statistics?from="+url.QueryEscape(time.Now().Add(-60*24*time.Hour).Format(time.RFC3339))+"&to="+url.QueryEscape(time.Now().Format(time.RFC3339)), nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get signin log statistics over 30 days for user status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/logs/statistics", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get signin log statistics as admin status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var adminStatisticsBody struct {
			Statistics struct {
				Countries []struct {
					CountryCode string `json:"countryCode"`
					Count       int64  `json:"count"`
				} `json:"countries"`
			} `json:"statistics"`
		}
		decodeJSONBody(t, resp, &adminStatisticsBody)
		if len(adminStatisticsBody.Statistics.Countries) != 2 {
			t.Fatalf("expected two countries in admin signin log statistics, got %#v", adminStatisticsBody)
		}
		if adminStatisticsBody.Statistics.Countries[0].CountryCode != "DE" || adminStatisticsBody.Statistics.Countries[0].Count != 2 {
			t.Fatalf("expected DE first in admin signin statistics, got %#v", adminStatisticsBody)
		}
		if adminStatisticsBody.Statistics.Countries[1].CountryCode != "US" || adminStatisticsBody.Statistics.Countries[1].Count != 1 {
			t.Fatalf("expected US historical log in admin signin statistics, got %#v", adminStatisticsBody)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/logs?page=1&size=10&country=DE", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get filtered signin logs status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var filteredLogsBody struct {
			Data []struct {
				Country     string `json:"country"`
				CountryCode string `json:"countryCode"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &filteredLogsBody)
		if len(filteredLogsBody.Data) < 2 {
			t.Fatalf("expected country-filtered signin logs, got %d", len(filteredLogsBody.Data))
		}
		for _, log := range filteredLogsBody.Data {
			if log.CountryCode != "DE" {
				t.Fatalf("expected filtered signin log country code to be DE, got %#v", filteredLogsBody.Data)
			}
		}

		// DELETE /v2/users/{user_id}/logs → force signout (excludes current session)
		resp = mustJSONRequest(t, env.server, http.MethodDelete, "/v2/users/"+userID+"/logs", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("force signout status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("mark signin tolerates missing metadata", func(t *testing.T) {
		username := "nologmeta" + uniqueSuffix()
		email := username + "@example.com"
		password := "nologmeta-pass-123"
		userID := mustCreateUser(t, env, username, password, email)
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		sessPayload, err := env.app.TokenServices().Session().Get(sessionToken)
		if err != nil {
			t.Fatalf("get session payload: %v", err)
		}
		if err := api.MarkSignIn(&sessPayload, nil, uuid.MustParse(userID)); err != nil {
			t.Fatalf("mark signin with nil metadata: %v", err)
		}

		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/logs?page=1&size=10", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get signin logs status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var logsBody struct {
			Data []struct {
				IP        string `json:"ip"`
				UserAgent string `json:"userAgent"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &logsBody)
		if len(logsBody.Data) != 1 {
			t.Fatalf("expected exactly 1 signin log entry, got %d", len(logsBody.Data))
		}
		if logsBody.Data[0].IP != "" || logsBody.Data[0].UserAgent != "" {
			t.Fatalf("expected blank metadata for nil signin log data, got %#v", logsBody.Data[0])
		}
	})

	t.Run("oauth2 token revocation invalidates access token", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope := "feature.revoke." + strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", ""))
		seedPermission(t, env, scope)

		// Get an access token via client credentials
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", map[string]any{
			"client_id":     client.clientID.String(),
			"client_secret": client.secret,
			"grant_type":    "client_credentials",
			"scope":         scope,
			"audience":      "https://api.example.com",
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("token exchange status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var tokenBody struct {
			AccessToken string `json:"access_token"`
		}
		decodeJSONBody(t, resp, &tokenBody)
		if tokenBody.AccessToken == "" {
			t.Fatalf("expected access token")
		}

		// Verify token is valid
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?access_token="+url.QueryEscape(tokenBody.AccessToken), nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("tokeninfo before revoke status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		resp.Body.Close()

		// Revoke the token
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{
			"token": {tokenBody.AccessToken},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("revoke token status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Verify token is no longer valid
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?access_token="+url.QueryEscape(tokenBody.AccessToken), nil, nil)
		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			t.Fatalf("expected revoked token to fail tokeninfo, but got 200")
		}
		resp.Body.Close()
	})

	t.Run("oauth2 refresh token revocation works", func(t *testing.T) {
		username := "revokerefresh" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "revoke-password-123", email)
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		// Authorize
		authQuery := fmt.Sprintf("/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(userID),
		)
		resp := mustJSONRequest(t, env.server, http.MethodPost, authQuery, nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("authorize status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var authBody struct {
			Code string `json:"code"`
		}
		decodeJSONBody(t, resp, &authBody)

		// Exchange for tokens
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", map[string]any{
			"client_id":     client.clientID.String(),
			"client_secret": client.secret,
			"code":          authBody.Code,
			"grant_type":    "authorization_code",
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("token exchange status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var tokenBody struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		decodeJSONBody(t, resp, &tokenBody)
		if tokenBody.RefreshToken == "" {
			t.Fatalf("expected refresh token for offline access")
		}

		// Revoke the refresh token
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{
			"token": {tokenBody.RefreshToken},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("revoke refresh token status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Verify refresh token no longer works
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", map[string]any{
			"client_id":     client.clientID.String(),
			"client_secret": client.secret,
			"refresh_token": tokenBody.RefreshToken,
			"grant_type":    "refresh_token",
		}, nil)
		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			t.Fatalf("expected revoked refresh token exchange to fail, but got 200")
		}
		resp.Body.Close()
	})

	t.Run("iforgot password reset via ownership token", func(t *testing.T) {
		username := "iforgot" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "old-password-123", email)

		// Create a verified ownership token manually
		manager := env.app.TokenServices().Ownership()
		content := tokens.OwnershipTokenContent{}
		content.SetEmailChallenge(email, "123456")
		content.EmailVerified = true
		ownershipToken, err := manager.New(content)
		if err != nil {
			t.Fatalf("create ownership token: %v", err)
		}

		// POST /v2/auth/iforgot
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/iforgot", map[string]any{
			"username":        username,
			"ownership_token": ownershipToken,
			"password":        "new-password-456",
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("iforgot status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Verify new password works
		var user database.User
		if err := env.db.Preload("Authenticators").First(&user, "id = ?", userID).Error; err != nil {
			t.Fatalf("load user: %v", err)
		}
		if !user.CheckPassword("new-password-456") {
			t.Fatalf("expected new password to work after iforgot")
		}
		if user.CheckPassword("old-password-123") {
			t.Fatalf("expected old password to no longer work")
		}
	})

	t.Run("iforgot rejects invalid ownership token", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/iforgot", map[string]any{
			"username":        "anyuser",
			"ownership_token": "bogus-token",
			"password":        "new-password-456",
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("iforgot invalid token status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("iforgot rejects missing required fields", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/iforgot", map[string]any{
			"password": "new-password-456",
		}, nil)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("iforgot missing fields status = %d, want %d, body=%s", resp.StatusCode, http.StatusUnprocessableEntity, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("user data lock get and set work for admin without prior userdata", func(t *testing.T) {
		username := "lockuser" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "lock-password-123", email)
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		// GET locks (initially empty)
		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/userdata/lock", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get locks status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var initialLocks map[string]any
		decodeJSONBody(t, resp, &initialLocks)
		if len(initialLocks) != 0 {
			t.Fatalf("expected no initial locks, got %#v", initialLocks)
		}

		// SET locks
		resp = mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/userdata/lock", map[string]any{
			"name": true,
		}, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("set locks status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Verify locks
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/userdata/lock", nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get locks after set status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var locks map[string]any
		decodeJSONBody(t, resp, &locks)
		if locks["name"] != true {
			t.Fatalf("expected name lock to be set, got %#v", locks)
		}

		var persistedUserData database.UserData
		if err := env.db.First(&persistedUserData, "user_id = ?", userID).Error; err != nil {
			t.Fatalf("load persisted user data after lock update: %v", err)
		}
	})

	t.Run("challenge with invalid token returns error", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/auth/challenge?token=invalid-token&for=signin", nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("invalid challenge token status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token=invalid-token&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue with invalid token status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token=invalid-token&type=password&for=signin", map[string]any{
			"response": "anything",
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate with invalid token status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("revoke with empty token returns error", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", map[string]any{
			"token": "",
		}, nil)
		// Huma validates required fields and returns 422, or API returns 400
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnprocessableEntity {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("revoke empty token status = %d, want 400 or 422, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()
	})

	// ============================================================
	// Challenge issue and verification tests
	// ============================================================

	t.Run("challenge issue without type returns 422", func(t *testing.T) {
		username := "chissue" + uniqueSuffix()
		email := username + "@example.com"
		mustCreateUser(t, env, username, "issue-pass-123", email)

		// Get a challenge token via signin
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)

		// Issue without type query param → should fail
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(signinBody.RequestToken)+"&for=signin", nil, nil)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue without type status = %d, want %d, body=%s", resp.StatusCode, http.StatusUnprocessableEntity, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("challenge validate with correct password without explicit issue succeeds", func(t *testing.T) {
		username := "directval" + uniqueSuffix()
		email := username + "@example.com"
		password := "directval-pass-123"
		mustCreateUser(t, env, username, password, email)
		sessionToken := mustCreateSessionToken(t, env)

		// Signin to get challenge token
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)

		// Validate password directly without explicit issue (password doesn't require challenge)
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("direct validate status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var validateBody struct {
			Passed bool `json:"passed"`
		}
		decodeJSONBody(t, resp, &validateBody)
		if !validateBody.Passed {
			t.Fatalf("expected direct password validation to pass")
		}

		// Complete signin
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       username,
			"challengeToken": signinBody.RequestToken,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin complete status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("challenge token reuse after signin revocation fails", func(t *testing.T) {
		username := "reuse" + uniqueSuffix()
		email := username + "@example.com"
		password := "reuse-pass-123"
		mustCreateUser(t, env, username, password, email)
		sessionToken := mustCreateSessionToken(t, env)

		// Signin to get challenge token
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)
		challengeToken := signinBody.RequestToken

		// Complete the full flow: issue → validate → signin
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       username,
			"challengeToken": challengeToken,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin complete status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Now try to reuse the revoked challenge token
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/auth/challenge?token="+url.QueryEscape(challengeToken)+"&for=signin", nil, nil)
		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			t.Fatalf("expected revoked challenge token to fail, but got 200")
		}
		resp.Body.Close()
	})

	t.Run("challenge get types returns password for user with only password authenticator", func(t *testing.T) {
		username := "chtypes" + uniqueSuffix()
		email := username + "@example.com"
		mustCreateUser(t, env, username, "types-pass-123", email)

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/auth/challenge?token="+url.QueryEscape(signinBody.RequestToken)+"&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get challenge types status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var types []string
		decodeJSONBody(t, resp, &types)
		if len(types) != 1 || types[0] != "password" {
			t.Fatalf("expected [password], got %#v", types)
		}
	})

	t.Run("challenge validate with empty response returns error", func(t *testing.T) {
		username := "emptyresp" + uniqueSuffix()
		email := username + "@example.com"
		mustCreateUser(t, env, username, "emptyresp-pass-123", email)

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)

		// Issue challenge first
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Validate with empty response
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", map[string]any{
			"response": "",
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("empty response validate status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("challenge get types for 2fa on user with totp authenticator", func(t *testing.T) {
		username := "totp2fa" + uniqueSuffix()
		email := username + "@example.com"
		password := "totp-pass-123"
		userID := mustCreateUser(t, env, username, password, email)

		// Seed a TOTP authenticator directly in the database
		totpSecret := "JBSWY3DPEHPK3PXP"
		totpAuth := database.UserAuthenticator{
			UserAuthenticatorFields: models.UserAuthenticatorFields{
				ID:                uuid.New(),
				Type:              "totp",
				Data:              map[string]any{"secret": totpSecret},
				UserID:            uuid.MustParse(userID),
				AllowSignIn:       false,
				Allow2FA:          true,
				AllowPasswordless: false,
				Note:              "test-totp",
			},
		}
		if err := env.db.Create(&totpAuth).Error; err != nil {
			t.Fatalf("create totp authenticator: %v", err)
		}

		// Enable 2FA on user
		env.db.Model(&database.User{}).Where("id = ?", userID).Update("2fa_enabled", true)

		sessionToken := mustCreateSessionToken(t, env)

		// Step 1: Signin
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)
		challengeToken := signinBody.RequestToken

		// Step 2: List challenge types for signin → should include password
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/auth/challenge?token="+url.QueryEscape(challengeToken)+"&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get signin types status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinTypes []string
		decodeJSONBody(t, resp, &signinTypes)
		foundPassword := false
		for _, ct := range signinTypes {
			if ct == "password" {
				foundPassword = true
			}
		}
		if !foundPassword {
			t.Fatalf("expected password in signin types, got %#v", signinTypes)
		}

		// Step 3: Complete password challenge
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue password status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate password status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Step 4: Signin with challenge token → should require 2FA
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       username,
			"challengeToken": challengeToken,
		}, bearerHeaders(sessionToken))
		// Without 2FA the user must not be added to the session.
		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()

			resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/debug/?token="+url.QueryEscape(sessionToken), nil, adminHeaders())
			if resp.StatusCode == http.StatusOK {
				var debugBody struct {
					Users []string `json:"users"`
				}
				decodeJSONBody(t, resp, &debugBody)
				for _, u := range debugBody.Users {
					if u == userID {
						t.Fatalf("user signed in without 2FA - expected 2FA requirement")
					}
				}
			}
		}
		resp.Body.Close()

		// Step 5: List 2FA types → should include totp
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/auth/challenge?token="+url.QueryEscape(challengeToken)+"&for=2fa", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get 2fa types status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var twoFATypes []string
		decodeJSONBody(t, resp, &twoFATypes)
		foundTOTP := false
		for _, ct := range twoFATypes {
			if ct == "totp" {
				foundTOTP = true
			}
		}
		if !foundTOTP {
			t.Fatalf("expected totp in 2fa types, got %#v", twoFATypes)
		}
	})

	t.Run("signin with 2fa totp completes full login flow end to end", func(t *testing.T) {
		username := "totpe2e" + uniqueSuffix()
		email := username + "@example.com"
		password := "totp-e2e-pass-123"
		userID := mustCreateUser(t, env, username, password, email)

		// Seed a TOTP authenticator directly in the database
		totpSecret := "JBSWY3DPEHPK3PXP"
		totpAuth := database.UserAuthenticator{
			UserAuthenticatorFields: models.UserAuthenticatorFields{
				ID:                uuid.New(),
				Type:              "totp",
				Data:              map[string]any{"secret": totpSecret},
				UserID:            uuid.MustParse(userID),
				AllowSignIn:       false,
				Allow2FA:          true,
				AllowPasswordless: false,
				Note:              "test-totp-e2e",
			},
		}
		if err := env.db.Create(&totpAuth).Error; err != nil {
			t.Fatalf("create totp authenticator: %v", err)
		}

		// Enable 2FA on user
		env.db.Model(&database.User{}).Where("id = ?", userID).Update("2fa_enabled", true)

		sessionToken := mustCreateSessionToken(t, env)

		// Step 1: Signin → get challenge token
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)
		challengeToken := signinBody.RequestToken

		// Step 2: Issue password challenge
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue password status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Step 3: Validate password
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate password status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Step 4: Try signin → should fail with two_factor_required
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       username,
			"challengeToken": challengeToken,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusUnauthorized {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin without 2fa status = %d, want 401, body=%s", resp.StatusCode, string(raw))
		}
		var twoFAErr map[string]any
		decodeJSONBody(t, resp, &twoFAErr)
		if twoFAErr["type"] != "two_factor_required" {
			t.Fatalf("expected type=two_factor_required, got %v", twoFAErr)
		}

		// Step 5: Generate a real TOTP code and validate it
		totpCode, err := totp.GenerateCode(totpSecret, time.Now())
		if err != nil {
			t.Fatalf("generate totp code: %v", err)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(challengeToken)+"&type=totp&for=2fa", map[string]any{
			"response": totpCode,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate totp status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Step 6: Signin should now succeed
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       username,
			"challengeToken": challengeToken,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("final signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Step 7: Verify user is actually in session
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/debug/?token="+url.QueryEscape(sessionToken), nil, adminHeaders())
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("session debug status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var debugBody struct {
			Users []string `json:"users"`
		}
		decodeJSONBody(t, resp, &debugBody)
		found := false
		for _, u := range debugBody.Users {
			if u == userID {
				found = true
			}
		}
		if !found {
			t.Fatalf("user %s not found in session users %v after 2FA signin", userID, debugBody.Users)
		}
	})

	t.Run("backup code works as recovery 2fa and is consumed", func(t *testing.T) {
		username := "backup2fa" + uniqueSuffix()
		email := username + "@example.com"
		password := "backup-e2e-pass-123"
		userID := mustCreateUser(t, env, username, password, email)

		totpAuth := database.UserAuthenticator{
			UserAuthenticatorFields: models.UserAuthenticatorFields{
				ID:                uuid.New(),
				Type:              "totp",
				Data:              map[string]any{"secret": "JBSWY3DPEHPK3PXP"},
				UserID:            uuid.MustParse(userID),
				AllowSignIn:       false,
				Allow2FA:          true,
				AllowPasswordless: false,
				Note:              "primary-totp",
			},
		}
		if err := env.db.Create(&totpAuth).Error; err != nil {
			t.Fatalf("create totp authenticator: %v", err)
		}
		env.db.Model(&database.User{}).Where("id = ?", userID).Update("2fa_enabled", true)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/"+userID+"/backup-codes/regenerate", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("regenerate backup codes status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var regenerateBody struct {
			Codes     []string `json:"codes"`
			Remaining int      `json:"remaining"`
		}
		decodeJSONBody(t, resp, &regenerateBody)
		if len(regenerateBody.Codes) != 10 || regenerateBody.Remaining != 10 {
			t.Fatalf("backup code response = %#v, want 10 codes and remaining=10", regenerateBody)
		}
		if !strings.Contains(regenerateBody.Codes[0], "-") {
			t.Fatalf("backup code should be human formatted, got %q", regenerateBody.Codes[0])
		}

		var backupAuthenticators []database.UserAuthenticator
		if err := env.db.Where("user_id = ? AND type = ?", userID, database.BackupCodeType).Find(&backupAuthenticators).Error; err != nil {
			t.Fatalf("find backup code authenticators: %v", err)
		}
		if len(backupAuthenticators) != 10 {
			t.Fatalf("stored backup code authenticators = %d, want 10", len(backupAuthenticators))
		}
		for _, authenticator := range backupAuthenticators {
			if _, ok := authenticator.Data["hash"].(string); !ok {
				t.Fatalf("backup code authenticator missing hash: %#v", authenticator.Data)
			}
			for _, code := range regenerateBody.Codes {
				if authenticator.Data["hash"] == code {
					t.Fatalf("backup code plaintext was stored in authenticator data")
				}
			}
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/backup-codes", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get backup codes status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var remainingBody struct {
			Remaining int `json:"remaining"`
		}
		decodeJSONBody(t, resp, &remainingBody)
		if remainingBody.Remaining != 10 {
			t.Fatalf("remaining backup codes = %d, want 10", remainingBody.Remaining)
		}

		signinSession := mustCreateSessionToken(t, env)
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, bearerHeaders(signinSession))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)
		challengeToken := signinBody.RequestToken

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue password status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate password status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/auth/challenge?token="+url.QueryEscape(challengeToken)+"&for=2fa", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get 2fa challenge types status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var twoFATypes []string
		decodeJSONBody(t, resp, &twoFATypes)
		foundBackupCode := false
		for _, challengeType := range twoFATypes {
			if challengeType == database.BackupCodeType {
				foundBackupCode = true
			}
		}
		if !foundBackupCode {
			t.Fatalf("expected backup_code in 2fa challenge types, got %#v", twoFATypes)
		}

		usedCode := regenerateBody.Codes[0]
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(challengeToken)+"&type=backup_code&for=2fa", map[string]any{
			"response": strings.ToLower(strings.ReplaceAll(usedCode, "-", " ")),
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate backup code status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       username,
			"challengeToken": challengeToken,
		}, bearerHeaders(signinSession))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("final signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/backup-codes", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get backup codes after use status = %d, body=%s", resp.StatusCode, string(raw))
		}
		decodeJSONBody(t, resp, &remainingBody)
		if remainingBody.Remaining != 9 {
			t.Fatalf("remaining backup codes after use = %d, want 9", remainingBody.Remaining)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/"+userID+"/backup-codes/regenerate", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("regenerate backup codes before delete status = %d, body=%s", resp.StatusCode, string(raw))
		}
		decodeJSONBody(t, resp, &regenerateBody)
		if len(regenerateBody.Codes) != 10 || regenerateBody.Remaining != 10 {
			t.Fatalf("backup code response before delete = %#v, want 10 codes and remaining=10", regenerateBody)
		}

		deletedCode := regenerateBody.Codes[0]
		resp = mustJSONRequest(t, env.server, http.MethodDelete, "/v2/users/"+userID+"/backup-codes", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("delete backup codes status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/"+userID+"/backup-codes", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get backup codes after delete status = %d, body=%s", resp.StatusCode, string(raw))
		}
		decodeJSONBody(t, resp, &remainingBody)
		if remainingBody.Remaining != 0 {
			t.Fatalf("remaining backup codes after delete = %d, want 0", remainingBody.Remaining)
		}

		var backupCodeRowsAfterDelete int64
		if err := env.db.Model(&database.UserAuthenticator{}).Where("user_id = ? AND type = ?", userID, database.BackupCodeType).Count(&backupCodeRowsAfterDelete).Error; err != nil {
			t.Fatalf("count backup code rows after delete: %v", err)
		}
		if backupCodeRowsAfterDelete != 0 {
			t.Fatalf("backup code rows after delete = %d, want 0", backupCodeRowsAfterDelete)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/"+userID+"/backup-codes/regenerate", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("regenerate backup codes after delete status = %d, body=%s", resp.StatusCode, string(raw))
		}
		decodeJSONBody(t, resp, &regenerateBody)
		if len(regenerateBody.Codes) != 10 || regenerateBody.Remaining != 10 {
			t.Fatalf("backup code response after delete = %#v, want 10 codes and remaining=10", regenerateBody)
		}

		reuseSession := mustCreateSessionToken(t, env)
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, bearerHeaders(reuseSession))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("reuse signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		decodeJSONBody(t, resp, &signinBody)
		reuseChallengeToken := signinBody.RequestToken

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(reuseChallengeToken)+"&type=password&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("reuse validate password status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(reuseChallengeToken)+"&type=backup_code&for=2fa", map[string]any{
			"response": deletedCode,
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("deleted backup code status = %d, want %d, body=%s", resp.StatusCode, http.StatusUnauthorized, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodDelete, "/v2/users/"+userID+"/totp?totp_id="+url.QueryEscape(totpAuth.ID.String()), nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("remove primary totp status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		var user database.User
		if err := env.db.First(&user, "id = ?", userID).Error; err != nil {
			t.Fatalf("find user after removing primary totp: %v", err)
		}
		if user.TwoFactorEnabled {
			t.Fatalf("two factor should be disabled after removing the last primary 2fa method")
		}

		var remainingBackupCodes int64
		if err := env.db.Model(&database.UserAuthenticator{}).Where("user_id = ? AND type = ?", userID, database.BackupCodeType).Count(&remainingBackupCodes).Error; err != nil {
			t.Fatalf("count remaining backup codes: %v", err)
		}
		if remainingBackupCodes != 0 {
			t.Fatalf("backup codes remaining after disabling 2fa = %d, want 0", remainingBackupCodes)
		}
	})

	t.Run("challenge issue for non-existent type returns error", func(t *testing.T) {
		username := "badtype" + uniqueSuffix()
		email := username + "@example.com"
		mustCreateUser(t, env, username, "badtype-pass-123", email)

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)

		// Issue for totp when user has no TOTP → should fail
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(signinBody.RequestToken)+"&type=totp&for=signin", nil, nil)
		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			t.Fatalf("expected issue for non-existent totp to fail, but got 200")
		}
		resp.Body.Close()
	})

	t.Run("challenge validate for wrong type returns error", func(t *testing.T) {
		username := "wrongtype" + uniqueSuffix()
		email := username + "@example.com"
		password := "wrongtype-pass-123"
		mustCreateUser(t, env, username, password, email)

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)

		// Issue password challenge
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(signinBody.RequestToken)+"&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Validate with otp type (wrong type) → should fail
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(signinBody.RequestToken)+"&type=otp&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode == http.StatusOK {
			var body struct {
				Passed bool `json:"passed"`
			}
			decodeJSONBody(t, resp, &body)
			if body.Passed {
				t.Fatalf("expected wrong type validation to not pass")
			}
		}
		resp.Body.Close()
	})

	t.Run("challenge get without for param lists all authenticator types", func(t *testing.T) {
		username := "nofor" + uniqueSuffix()
		email := username + "@example.com"
		mustCreateUser(t, env, username, "nofor-pass-123", email)

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)

		// Get challenge types without 'for' param
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/auth/challenge?token="+url.QueryEscape(signinBody.RequestToken), nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get types no for status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var types []string
		decodeJSONBody(t, resp, &types)
		if len(types) == 0 {
			t.Fatalf("expected at least one type, got empty list")
		}
	})

	t.Run("verification token issue and revoke flow", func(t *testing.T) {
		manager := env.app.TokenServices().Verification()

		payload := tokens.VerificationMergedPayload{
			VerificationPayload: tokens.VerificationPayload{
				Email: "verify-test@example.com",
			},
			VerificationServerPayload: tokens.VerificationServerPayload{
				Challenge: "123456",
			},
		}
		token, err := manager.New(payload)
		if err != nil {
			t.Fatalf("new verification token: %v", err)
		}
		if token == "" {
			t.Fatalf("expected non-empty verification token")
		}

		// Token should not be revoked initially
		if manager.IsRevoked(token) {
			t.Fatalf("expected token to not be revoked initially")
		}

		// Revoke the token
		if err := manager.Revoke(token); err != nil {
			t.Fatalf("revoke verification token: %v", err)
		}

		// After revoke, token should be revoked
		if !manager.IsRevoked(token) {
			t.Fatalf("expected token to be revoked after revoke")
		}
	})

	t.Run("challenge manager lifecycle: new get set revoke", func(t *testing.T) {
		manager := env.app.TokenServices().Challenge()

		data := tokens.ChallengeContent{
			UserID:           "lifecycle-user",
			PassedChallenges: []string{},
		}
		token, err := manager.New(data)
		if err != nil {
			t.Fatalf("new challenge token: %v", err)
		}
		if token == "" {
			t.Fatalf("expected non-empty challenge token")
		}

		// Get
		got, err := manager.Get(token)
		if err != nil {
			t.Fatalf("get challenge token: %v", err)
		}
		if got.UserID != "lifecycle-user" {
			t.Fatalf("expected user lifecycle-user, got %q", got.UserID)
		}

		// Set (update)
		got.UserID = "updated-user-id"
		if err := manager.Set(token, got); err != nil {
			t.Fatalf("set challenge token: %v", err)
		}
		updated, err := manager.Get(token)
		if err != nil {
			t.Fatalf("get updated token: %v", err)
		}
		if updated.UserID != "updated-user-id" {
			t.Fatalf("expected updated user id, got %q", updated.UserID)
		}

		// Revoke
		if err := manager.Revoke(token); err != nil {
			t.Fatalf("revoke challenge token: %v", err)
		}
		if !manager.IsRevoked(token) {
			t.Fatalf("expected challenge token to be revoked")
		}

		// Double revoke should error
		err = manager.Revoke(token)
		if err == nil {
			t.Fatalf("expected error revoking already-revoked token")
		}
	})

	t.Run("challenge content mark passed and check passed", func(t *testing.T) {
		content := tokens.ChallengeContent{
			PassedChallenges: []string{},
		}

		authID := uuid.NewString()
		if content.IsPassed(authID) {
			t.Fatalf("expected authID to not be passed initially")
		}

		content.MarkAsPassed(authID)
		if !content.IsPassed(authID) {
			t.Fatalf("expected authID to be passed after marking")
		}

		// Different ID should not be passed
		otherID := uuid.NewString()
		if content.IsPassed(otherID) {
			t.Fatalf("expected other authID to not be passed")
		}
	})

	t.Run("challenge content set and reset challenge", func(t *testing.T) {
		content := tokens.ChallengeContent{}

		ids := []string{uuid.NewString(), uuid.NewString()}
		content.SetChallenge(ids, "response-data", time.Now().Add(time.Hour))

		if len(content.ChallengeIds) != 2 {
			t.Fatalf("expected 2 challenge IDs, got %d", len(content.ChallengeIds))
		}
		if content.ChallengeResponse != "response-data" {
			t.Fatalf("expected response-data, got %q", content.ChallengeResponse)
		}
		if content.IsExpired() {
			t.Fatalf("expected challenge to not be expired")
		}

		content.ResetChallenge()
		if len(content.ChallengeIds) != 0 {
			t.Fatalf("expected empty challenge IDs after reset, got %d", len(content.ChallengeIds))
		}
		if content.ChallengeResponse != "" {
			t.Fatalf("expected empty response after reset, got %q", content.ChallengeResponse)
		}
	})

	t.Run("challenge content expired check", func(t *testing.T) {
		content := tokens.ChallengeContent{}
		content.SetChallenge([]string{"id"}, "resp", time.Now().Add(-time.Hour))

		if !content.IsExpired() {
			t.Fatalf("expected challenge set in the past to be expired")
		}

		content.SetChallenge([]string{"id"}, "resp", time.Now().Add(time.Hour))
		if content.IsExpired() {
			t.Fatalf("expected challenge set in the future to not be expired")
		}
	})

	t.Run("ownership token email verification flow", func(t *testing.T) {
		manager := env.app.TokenServices().Ownership()

		content := tokens.OwnershipTokenContent{}
		content.SetEmailChallenge("owner@example.com", "654321")

		token, err := manager.New(content)
		if err != nil {
			t.Fatalf("new ownership token: %v", err)
		}

		// Get and verify challenge
		got, err := manager.Get(token)
		if err != nil {
			t.Fatalf("get ownership token: %v", err)
		}
		if got.Email != "owner@example.com" {
			t.Fatalf("expected email owner@example.com, got %q", got.Email)
		}

		// Verify email challenge
		if !got.VerifyEmailChallenge("owner@example.com", "654321") {
			t.Fatalf("expected email challenge to verify")
		}

		// Wrong challenge should fail
		if got.VerifyEmailChallenge("owner@example.com", "000000") {
			t.Fatalf("expected wrong challenge to fail")
		}

		// Wrong email should fail
		if got.VerifyEmailChallenge("wrong@example.com", "654321") {
			t.Fatalf("expected wrong email to fail")
		}

		// Mark verified and update
		got.EmailVerified = true
		if err := manager.Set(token, got); err != nil {
			t.Fatalf("set ownership token: %v", err)
		}

		updated, err := manager.Get(token)
		if err != nil {
			t.Fatalf("get updated ownership token: %v", err)
		}
		if !updated.IsEmailVerified("owner@example.com") {
			t.Fatalf("expected email to be verified after update")
		}

		// Revoke
		if err := manager.Revoke(token); err != nil {
			t.Fatalf("revoke ownership token: %v", err)
		}
		if !manager.IsRevoked(token) {
			t.Fatalf("expected ownership token to be revoked")
		}
	})

	t.Run("ownership token phone verification flow", func(t *testing.T) {
		manager := env.app.TokenServices().Ownership()

		content := tokens.OwnershipTokenContent{}
		content.SetPhoneChallenge("+14155550123", "789012")

		token, err := manager.New(content)
		if err != nil {
			t.Fatalf("new ownership token: %v", err)
		}

		got, err := manager.Get(token)
		if err != nil {
			t.Fatalf("get ownership token: %v", err)
		}

		if !got.VerifyPhoneChallenge("+14155550123", "789012") {
			t.Fatalf("expected phone challenge to verify")
		}

		if got.VerifyPhoneChallenge("+14155550123", "000000") {
			t.Fatalf("expected wrong phone challenge to fail")
		}

		if got.VerifyPhoneChallenge("+14155550199", "789012") {
			t.Fatalf("expected wrong phone number to fail")
		}
	})

	t.Run("signin with unverified email finds user when verification not required", func(t *testing.T) {
		// Create user with unverified email via signup API (not admin API which sets verified=true)
		suffix := uniqueSuffix()
		email := "unverified" + suffix + "@example.com"
		password := "unverified-pass-123"

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signup", map[string]any{
			"email":    email,
			"password": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signup status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Signin using the unverified email should succeed (get challenge token)
		sessionToken := mustCreateSessionToken(t, env)
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": email,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin with unverified email status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var signinBody struct {
			Action       string `json:"action"`
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)
		if signinBody.Action != "challenge" || signinBody.RequestToken == "" {
			t.Fatalf("expected challenge action with token for unverified email signin, got %#v", signinBody)
		}
	})

	t.Run("list users with bypass returns data after signin", func(t *testing.T) {
		username := "bypasslist" + uniqueSuffix()
		email := username + "@example.com"
		password := "bypasslist-pass-123"
		userID := mustCreateUser(t, env, username, password, email)
		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		// GET /v2/users with bypass=true should return the user
		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/?bypass=true", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("list users bypass status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var listBody struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Pagination struct {
				Total  int64 `json:"total"`
				Bypass bool  `json:"bypass"`
			} `json:"pagination"`
		}
		decodeJSONBody(t, resp, &listBody)

		if !listBody.Pagination.Bypass {
			t.Fatalf("expected bypass=true in pagination, got %#v", listBody.Pagination)
		}
		if listBody.Pagination.Total == 0 {
			t.Fatalf("expected total > 0, got 0")
		}
		if len(listBody.Data) == 0 {
			t.Fatalf("expected data to contain users when bypass=true, got empty array (total=%d)", listBody.Pagination.Total)
		}
		found := false
		for _, u := range listBody.Data {
			if u.ID == userID {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected user %q in bypass list, got %#v", userID, listBody.Data)
		}
	})

	t.Run("signin completes and list users returns signed-in user", func(t *testing.T) {
		username := "fullflow" + uniqueSuffix()
		email := username + "@example.com"
		password := "fullflow-pass-123"
		userID := mustCreateUser(t, env, username, password, email)
		sessionToken := mustCreateSessionToken(t, env)

		// Full signin flow
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var signinBody struct {
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinBody)
		challengeToken := signinBody.RequestToken

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("issue challenge status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/validate?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin", map[string]any{
			"response": password,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate challenge status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       username,
			"challengeToken": challengeToken,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin complete status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		resp.Body.Close()

		// Now list users with bypass - should see the signed-in user
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/users/?bypass=true", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("list users status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}
		var listBody struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		decodeJSONBody(t, resp, &listBody)
		if len(listBody.Data) == 0 {
			t.Fatalf("expected signed-in user in list, got empty data")
		}
		found := false
		for _, u := range listBody.Data {
			if u.ID == userID {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected user %q in list after signin, got %#v", userID, listBody.Data)
		}
	})
}
