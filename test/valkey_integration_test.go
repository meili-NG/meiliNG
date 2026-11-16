package test

import (
	meiling "github.com/meili-NG/meiliNG/v2"

	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/server/webui"
)

func valkeyAvailable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func newFeatureEnvWithValkey(t *testing.T, valkeyAddr string) *featureEnv {
	t.Helper()

	database.ResetInstance()
	dir := t.TempDir()
	appInstance, err := meiling.New(config.MeilingConfig{
		InstanceConfig: config.InstanceConfig{Name: "Meiling Valkey Test"},
		ServerConfig:   config.ServerConfig{PublicURL: "https://api.example.com"},
		OAuth2Config:   config.OAuth2Config{ConsentFrontends: []string{"https://accounts.example.com/auth"}},
		DatabaseConfig: config.DatabaseConfig{
			Type: "sqlite",
			DSN:  filepath.Join(dir, "meiling-valkey-test.sqlite"),
		},
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:      "RS256",
			PrivateKeyPath: filepath.Join(dir, "jwt.key"),
			PublicKeyPath:  filepath.Join(dir, "jwt.pub"),
		}},
		ValkeyConfig: config.ValkeyConfig{
			InitAddress:   []string{valkeyAddr},
			TimeoutString: "5s",
		},
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
	})
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

func TestValkeyIntegration(t *testing.T) {
	const valkeyAddr = "localhost:6399"
	if !valkeyAvailable(valkeyAddr) {
		t.Skip("Valkey/Redis not available at " + valkeyAddr)
	}

	env := newFeatureEnvWithValkey(t, valkeyAddr)

	t.Run("session create and validate with valkey backing", func(t *testing.T) {
		sessionToken := mustCreateSessionToken(t, env)

		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/sessions/", nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate session status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()
	})

	t.Run("oauth2 client credentials flow with valkey", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope := "valkey.m2m." + uniqueSuffix()
		seedPermission(t, env, scope)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"grant_type":    {"client_credentials"},
			"scope":         {scope},
			"audience":      {"https://api.example.com"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("token exchange status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var tokenBody struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			Scope       string `json:"scope"`
		}
		decodeJSONBody(t, resp, &tokenBody)
		if tokenBody.AccessToken == "" || tokenBody.TokenType != "Bearer" || tokenBody.Scope != scope {
			t.Fatalf("unexpected token response: %+v", tokenBody)
		}

		// Verify tokeninfo works (reads back from valkey)
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?access_token="+url.QueryEscape(tokenBody.AccessToken), nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("tokeninfo status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Revoke and verify it's rejected
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{
			"token": {tokenBody.AccessToken},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("revoke status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?access_token="+url.QueryEscape(tokenBody.AccessToken), nil, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected tokeninfo to fail for revoked token")
		}
		resp.Body.Close()
	})

	t.Run("sign-in challenge validate flow with valkey", func(t *testing.T) {
		username := "valkeyuser" + uniqueSuffix()
		email := username + "@example.com"
		password := "valkey-test-password-123"
		userID := mustCreateUser(t, env, username, password, email)

		sessionToken := mustCreateSessionToken(t, env)

		// Step 1: signin → get challenge token
		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("signin status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var signinResp struct {
			Action       string `json:"action"`
			RequestToken string `json:"requestToken"`
		}
		decodeJSONBody(t, resp, &signinResp)
		if signinResp.Action != "challenge" || signinResp.RequestToken == "" {
			t.Fatalf("unexpected signin response: %+v", signinResp)
		}

		challengeToken := signinResp.RequestToken

		// Step 2: get available challenge types
		resp = mustJSONRequest(t, env.server, http.MethodGet,
			"/v2/auth/challenge?token="+url.QueryEscape(challengeToken)+"&for=signin",
			nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("get challenge types status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var challengeTypes []string
		decodeJSONBody(t, resp, &challengeTypes)
		if len(challengeTypes) == 0 {
			t.Fatal("expected at least one challenge type")
		}

		hasPassword := false
		for _, ct := range challengeTypes {
			if ct == "password" {
				hasPassword = true
			}
		}
		if !hasPassword {
			t.Fatalf("expected password challenge type, got %v", challengeTypes)
		}

		// Step 3: validate with a wrong password; the request must fail
		resp = mustJSONRequest(t, env.server, http.MethodPost,
			"/v2/auth/challenge/validate?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin",
			map[string]any{"response": "wrong-password"},
			nil)
		if resp.StatusCode == http.StatusOK {
			var body map[string]any
			decodeJSONBody(t, resp, &body)
			if body["passed"] == true {
				t.Fatal("expected wrong password to fail")
			}
		} else {
			// 400 is expected for invalid challenge response
			resp.Body.Close()
		}

		// Step 4: validate with CORRECT password
		// Need a fresh challenge token since the previous one may be consumed
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username": username,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("second signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		decodeJSONBody(t, resp, &signinResp)
		challengeToken = signinResp.RequestToken

		resp = mustJSONRequest(t, env.server, http.MethodPost,
			"/v2/auth/challenge/validate?token="+url.QueryEscape(challengeToken)+"&type=password&for=signin",
			map[string]any{"response": password},
			nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("validate correct password status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var validateResp struct {
			Passed bool `json:"passed"`
		}
		decodeJSONBody(t, resp, &validateResp)
		if !validateResp.Passed {
			t.Fatal("expected correct password to pass")
		}

		// Step 5: complete signin with challenge token
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{
			"username":       username,
			"challengeToken": challengeToken,
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("complete signin status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Step 6: verify user is now in session
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
		if len(debugBody.Users) == 0 {
			t.Fatal("expected user in session after signin")
		}
		found := false
		for _, u := range debugBody.Users {
			if u == userID {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected user %s in session, got %v", userID, debugBody.Users)
		}
	})

	t.Run("authorization code flow with valkey", func(t *testing.T) {
		username := "valkeyoidc" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "valkey-oidc-pass", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")
		ensurePermissionScope(t, env, "profile")

		// Authorize
		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&nonce=valkey-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid profile"),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(userID),
		)
		resp := mustJSONRequest(t, env.server, http.MethodPost, authorizeQuery, nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("authorize status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var authResp struct {
			Code string `json:"code"`
		}
		decodeJSONBody(t, resp, &authResp)
		if authResp.Code == "" {
			t.Fatal("expected non-empty authorization code")
		}

		// Exchange code for tokens
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"code":          {authResp.Code},
			"grant_type":    {"authorization_code"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("token exchange status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var tokenResp struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			TokenType    string `json:"token_type"`
		}
		decodeJSONBody(t, resp, &tokenResp)
		if tokenResp.AccessToken == "" || tokenResp.TokenType != "Bearer" {
			t.Fatalf("unexpected token response: %+v", tokenResp)
		}
		if tokenResp.RefreshToken == "" {
			t.Fatal("expected refresh_token for offline access")
		}

		// Userinfo
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/userinfo", nil, bearerHeaders(tokenResp.AccessToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("userinfo status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var userInfo struct {
			Sub               string `json:"sub"`
			PreferredUsername string `json:"preferred_username"`
		}
		decodeJSONBody(t, resp, &userInfo)
		if userInfo.Sub != userID {
			t.Fatalf("sub = %q, want %q", userInfo.Sub, userID)
		}

		// Refresh
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {tokenResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("refresh status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var refreshResp struct {
			AccessToken string `json:"access_token"`
		}
		decodeJSONBody(t, resp, &refreshResp)
		if refreshResp.AccessToken == "" {
			t.Fatal("expected non-empty access_token from refresh")
		}
	})

	t.Run("valkey timeout config is respected", func(t *testing.T) {
		cfg := env.app.TokenServices().Config()
		if cfg.ValkeyConfig.Timeout != 5*time.Second {
			t.Fatalf("ValkeyConfig.Timeout = %v, want 5s", cfg.ValkeyConfig.Timeout)
		}

		global := env.app.TokenServices().Global()
		if !global.IsValkeyEnabled() {
			t.Fatal("expected valkey to be enabled")
		}
	})

	t.Run("tokens survive across reads from valkey", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope := "valkey.persist." + uniqueSuffix()
		seedPermission(t, env, scope)

		// Issue token
		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"grant_type":    {"client_credentials"},
			"scope":         {scope},
			"audience":      {"https://api.example.com"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("token status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var tokenBody struct {
			AccessToken string `json:"access_token"`
		}
		decodeJSONBody(t, resp, &tokenBody)

		// Read multiple times — valkey should return consistent data
		for i := 0; i < 3; i++ {
			resp = mustJSONRequest(t, env.server, http.MethodGet,
				"/v2/oauth2/tokeninfo?access_token="+url.QueryEscape(tokenBody.AccessToken), nil, nil)
			if resp.StatusCode != http.StatusOK {
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				t.Fatalf("tokeninfo read %d status = %d, body=%s", i+1, resp.StatusCode, string(raw))
			}
			var info struct {
				AccessToken string `json:"access_token"`
				Scope       string `json:"scope"`
			}
			decodeJSONBody(t, resp, &info)
			if info.AccessToken != tokenBody.AccessToken {
				t.Fatalf("read %d: access_token mismatch", i+1)
			}
			if info.Scope != scope {
				t.Fatalf("read %d: scope = %q, want %q", i+1, info.Scope, scope)
			}
		}
	})

	t.Run("a revoked magic admin token is rejected on every path", func(t *testing.T) {
		cfg := env.app.Config()
		cfg.WebUIConfig.Enable = true
		cfg.WebUIConfig.ProvideAdminURL = true
		services := env.app.TokenServices()

		magic := webui.ProvisionSharedAdminToken(cfg, services)
		if magic == "" {
			t.Fatal("no magic admin token was provisioned")
		}
		authorization := "Meiling-Admin-Token " + magic

		// One route behind the admin check, one behind the session check.
		paths := []string{"/v2/oauth2/audiences/", "/v2/users/?page=1&size=1&all=true"}
		status := func(path string) int {
			resp := mustJSONRequest(t, env.server, http.MethodGet, path, nil, map[string]string{"Authorization": authorization})
			resp.Body.Close()
			return resp.StatusCode
		}

		for _, path := range paths {
			if got := status(path); got != http.StatusOK {
				t.Fatalf("GET %s with the magic token = %d, want %d", path, got, http.StatusOK)
			}
		}
		if _, err := api.ParseAuthorization(cfg, services, authorization); err != nil {
			t.Fatalf("ParseAuthorization with the magic token: %v", err)
		}

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{"token": {magic}}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("revoke status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		for _, path := range paths {
			if got := status(path); got != http.StatusUnauthorized {
				t.Fatalf("GET %s with the revoked magic token = %d, want %d", path, got, http.StatusUnauthorized)
			}
		}
		if _, err := api.ParseAuthorization(cfg, services, authorization); err == nil {
			t.Fatal("ParseAuthorization accepts the revoked magic token")
		}
	})
}
