package test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

func TestOAuth2Flows(t *testing.T) {
	env := newFeatureEnv(t)

	// ==================== M2M / Client Credentials ====================

	t.Run("m2m client credentials grant returns access token with correct payload", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope := "m2m.read." + uniqueSuffix()
		permID := seedPermission(t, env, scope)

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
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}

		var body struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Scope       string `json:"scope"`
		}
		decodeJSONBody(t, resp, &body)

		if body.AccessToken == "" {
			t.Fatal("expected non-empty access_token")
		}
		if body.TokenType != "Bearer" {
			t.Fatalf("token_type = %q, want Bearer", body.TokenType)
		}
		if body.ExpiresIn <= 0 {
			t.Fatalf("expires_in = %d, want > 0", body.ExpiresIn)
		}
		if body.Scope != scope {
			t.Fatalf("scope = %q, want %q", body.Scope, scope)
		}

		payload, err := env.app.TokenServices().AccessToken().Get(body.AccessToken)
		if err != nil {
			t.Fatalf("get access token: %v", err)
		}
		if payload.ClientID != client.clientID.String() {
			t.Fatalf("ClientID = %q, want %q", payload.ClientID, client.clientID.String())
		}
		if payload.GrantType != "client_credentials" {
			t.Fatalf("GrantType = %q, want client_credentials", payload.GrantType)
		}
		if len(payload.Permissions) != 1 || payload.Permissions[0] != permID.String() {
			t.Fatalf("Permissions = %v, want [%s]", payload.Permissions, permID)
		}
		if len(payload.Audience) != 1 || payload.Audience[0] != "https://api.example.com" {
			t.Fatalf("Audience = %v", payload.Audience)
		}

		claims, err := env.app.TokenServices().JWT().ParseTokenClaims(body.AccessToken)
		if err != nil {
			t.Fatalf("parse access token claims: %v", err)
		}
		if claims.Subject != client.clientID.String() {
			t.Fatalf("sub = %q, want %q", claims.Subject, client.clientID.String())
		}
	})

	t.Run("m2m client credentials with multiple scopes and audiences", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope1 := "m2m.multi1." + uniqueSuffix()
		scope2 := "m2m.multi2." + uniqueSuffix()
		seedPermission(t, env, scope1)
		seedPermission(t, env, scope2)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"grant_type":    {"client_credentials"},
			"scope":         {scope1 + " " + scope2},
			"audience":      {"https://api1.example.com https://api2.example.com"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}

		var body struct {
			AccessToken string `json:"access_token"`
			Scope       string `json:"scope"`
		}
		decodeJSONBody(t, resp, &body)

		scopes := strings.Fields(body.Scope)
		if len(scopes) != 2 {
			t.Fatalf("expected 2 scopes, got %d: %q", len(scopes), body.Scope)
		}

		payload, err := env.app.TokenServices().AccessToken().Get(body.AccessToken)
		if err != nil {
			t.Fatalf("get access token: %v", err)
		}
		if len(payload.Audience) != 2 {
			t.Fatalf("Audience = %v, want 2 entries", payload.Audience)
		}
		if len(payload.Permissions) != 2 {
			t.Fatalf("Permissions = %v, want 2 entries", payload.Permissions)
		}
	})

	t.Run("m2m client credentials with basic auth header", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope := "m2m.basic." + uniqueSuffix()
		seedPermission(t, env, scope)

		basicAuth := base64.StdEncoding.EncodeToString(
			[]byte(client.clientID.String() + ":" + client.secret),
		)

		// Basic auth still requires client_id in the body for the framework validator
		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":  {client.clientID.String()},
			"grant_type": {"client_credentials"},
			"scope":      {scope},
			"audience":   {"https://api.example.com"},
		}, map[string]string{
			"Authorization": "Basic " + basicAuth,
		})
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
		}

		var body struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}
		decodeJSONBody(t, resp, &body)
		if body.AccessToken == "" || body.TokenType != "Bearer" {
			t.Fatalf("unexpected response: %+v", body)
		}
	})

	t.Run("m2m client credentials tokeninfo roundtrip via GET and POST", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope := "m2m.info." + uniqueSuffix()
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
		}
		decodeJSONBody(t, resp, &tokenBody)

		// GET tokeninfo
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?access_token="+url.QueryEscape(tokenBody.AccessToken), nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("GET tokeninfo status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var info struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			Scope       string `json:"scope"`
		}
		decodeJSONBody(t, resp, &info)
		if info.AccessToken != tokenBody.AccessToken {
			t.Fatalf("tokeninfo access_token mismatch")
		}
		if info.TokenType != "Bearer" {
			t.Fatalf("tokeninfo token_type = %q", info.TokenType)
		}
		if info.Scope != scope {
			t.Fatalf("tokeninfo scope = %q, want %q", info.Scope, scope)
		}

		// POST tokeninfo
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/tokeninfo", url.Values{
			"access_token": {tokenBody.AccessToken},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("POST tokeninfo status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var postInfo struct {
			AccessToken string `json:"access_token"`
			Scope       string `json:"scope"`
		}
		decodeJSONBody(t, resp, &postInfo)
		if postInfo.AccessToken != tokenBody.AccessToken || postInfo.Scope != scope {
			t.Fatalf("POST tokeninfo mismatch: %+v", postInfo)
		}
	})

	t.Run("m2m token revocation invalidates token", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope := "m2m.revoke." + uniqueSuffix()
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
		}
		decodeJSONBody(t, resp, &tokenBody)

		// Revoke
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{
			"token": {tokenBody.AccessToken},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("revoke status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// tokeninfo should fail for revoked token
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?access_token="+url.QueryEscape(tokenBody.AccessToken), nil, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected tokeninfo to fail for revoked token")
		}
		resp.Body.Close()
	})

	t.Run("m2m error: invalid client_secret returns OAuth2 invalid_client", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {"wrong-secret"},
			"grant_type":    {"client_credentials"},
			"scope":         {"anything"},
			"audience":      {"https://api.example.com"},
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "unauthorized_client" {
			t.Fatalf("expected error=unauthorized_client, got %v", errBody)
		}
	})

	t.Run("m2m error: public client_credentials without secret returns OAuth2 invalid_client", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, false)
		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":  {client.clientID.String()},
			"grant_type": {"client_credentials"},
			"scope":      {"anything"},
			"audience":   {"https://api.example.com"},
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_client" {
			t.Fatalf("expected error=invalid_client, got %v", errBody)
		}
	})

	t.Run("m2m error: unsupported grant_type returns OAuth2 unsupported_grant_type", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"grant_type":    {"unsupported_grant"},
		}, nil)

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "unsupported_grant_type" {
			t.Fatalf("expected error=unsupported_grant_type, got %v", errBody)
		}
	})

	t.Run("m2m error: client_credentials without audience returns OAuth2 invalid_request", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope := "m2m.noaud." + uniqueSuffix()
		seedPermission(t, env, scope)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"grant_type":    {"client_credentials"},
			"scope":         {scope},
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_request" {
			t.Fatalf("expected error=invalid_request, got %v", errBody)
		}
	})

	t.Run("m2m error: nonexistent client returns OAuth2 invalid_client", func(t *testing.T) {
		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {"00000000-0000-0000-0000-000000000000"},
			"client_secret": {"doesnt-matter"},
			"grant_type":    {"client_credentials"},
			"scope":         {"anything"},
			"audience":      {"https://api.example.com"},
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_client" {
			t.Fatalf("expected error=invalid_client, got %v", errBody)
		}
	})

	t.Run("m2m error: invalid scope returns OAuth2 invalid_scope", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"grant_type":    {"client_credentials"},
			"scope":         {"nonexistent.scope." + uniqueSuffix()},
			"audience":      {"https://api.example.com"},
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_scope" {
			t.Fatalf("expected error=invalid_scope, got %v", errBody)
		}
	})

	t.Run("m2m error: revoke with empty token returns OAuth2 invalid_request", func(t *testing.T) {
		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{
			"token": {""},
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_request" {
			t.Fatalf("expected error=invalid_request, got %v", errBody)
		}
	})

	t.Run("m2m error: tokeninfo with no token returns OAuth2 invalid_request", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo", nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_request" {
			t.Fatalf("expected error=invalid_request, got %v", errBody)
		}
	})

	t.Run("m2m error: tokeninfo with invalid token returns OAuth2 error", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?access_token=invalid-jwt-token", nil, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected failure for invalid token")
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] == nil {
			t.Fatalf("expected OAuth2 error format, got %v", errBody)
		}
	})

	// ==================== Authorization Code / OpenID Connect ====================

	t.Run("oidc full authorization code flow with consent and token exchange", func(t *testing.T) {
		username := "oidcuser" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-oidc", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)
		resp := mustJSONRequest(t, env.server, http.MethodPut, "/v2/users/"+userID+"/userdata", map[string]any{
			"language": "en-US",
			"timezone": "Europe/Paris",
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("update user locale data status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")
		ensurePermissionScope(t, env, "profile")
		ensurePermissionScope(t, env, "email")

		fullScope := "openid profile email"

		// Step 1: Check consent requirement
		authQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s",
			client.clientID.String(),
			url.QueryEscape(fullScope),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(userID),
		)
		resp = mustJSONRequest(t, env.server, http.MethodGet, authQuery, nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("consent check status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var consentBody struct {
			UserConsentRequired bool `json:"userConsentRequired"`
		}
		decodeJSONBody(t, resp, &consentBody)

		// Step 2: Authorize (issue code) with offline access
		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&state=test-state-123&nonce=test-nonce-456&approve=true",
			client.clientID.String(),
			url.QueryEscape(fullScope),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(userID),
		)
		resp = mustJSONRequest(t, env.server, http.MethodPost, authorizeQuery, nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("authorize status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var authResp struct {
			Code   string `json:"code"`
			Tokens any    `json:"tokens"`
		}
		decodeJSONBody(t, resp, &authResp)
		if authResp.Code == "" {
			t.Fatal("expected non-empty authorization code")
		}

		codeClaims, err := env.app.TokenServices().JWT().ParseTokenClaims(authResp.Code)
		if err != nil {
			t.Fatalf("parse authorization code claims: %v", err)
		}
		if codeClaims.Subject != userID {
			t.Fatalf("authorization code sub = %q, want %q", codeClaims.Subject, userID)
		}

		// Step 3: Exchange code for tokens. Concurrent exchanges of the same
		// code issue tokens once; the others get invalid_grant.
		exchanges := make(chan *http.Response, 8)
		for range cap(exchanges) {
			go func() {
				exchanges <- mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
					"client_id":     {client.clientID.String()},
					"client_secret": {client.secret},
					"code":          {authResp.Code},
					"grant_type":    {"authorization_code"},
				}, nil)
			}()
		}
		resp = nil
		for range cap(exchanges) {
			r := <-exchanges
			if r.StatusCode == http.StatusOK && resp == nil {
				resp = r
				continue
			}
			raw, _ := io.ReadAll(r.Body)
			r.Body.Close()
			if r.StatusCode == http.StatusOK || !strings.Contains(string(raw), "invalid_grant") {
				t.Fatalf("concurrent exchange of a redeemed code = %d %s, want only one success", r.StatusCode, raw)
			}
		}
		if resp == nil {
			t.Fatal("no concurrent token exchange succeeded")
		}

		var tokenResp struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			IdToken      string `json:"id_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
			Scope        string `json:"scope"`
		}
		decodeJSONBody(t, resp, &tokenResp)

		if tokenResp.AccessToken == "" {
			t.Fatal("expected non-empty access_token")
		}
		if tokenResp.TokenType != "Bearer" {
			t.Fatalf("token_type = %q, want Bearer", tokenResp.TokenType)
		}
		if tokenResp.ExpiresIn <= 0 {
			t.Fatalf("expires_in = %d, want > 0", tokenResp.ExpiresIn)
		}
		if tokenResp.RefreshToken == "" {
			t.Fatal("expected non-empty refresh_token for offline access")
		}
		if tokenResp.IdToken == "" {
			t.Fatal("expected non-empty id_token for openid scope")
		}
		var idTokenContent tokens.IDTokenContent
		if err := env.app.TokenServices().JWT().ParseTokenCustomClaims(tokenResp.IdToken, &idTokenContent); err != nil {
			t.Fatalf("parse id token custom claims: %v", err)
		}
		if idTokenContent.Locale == nil || *idTokenContent.Locale != "en-US" {
			t.Fatalf("id token locale = %v, want en-US", idTokenContent.Locale)
		}
		if idTokenContent.ZoneInfo == nil || *idTokenContent.ZoneInfo != "Europe/Paris" {
			t.Fatalf("id token zoneinfo = %v, want Europe/Paris", idTokenContent.ZoneInfo)
		}

		// Verify access token payload
		payload, err := env.app.TokenServices().AccessToken().Get(tokenResp.AccessToken)
		if err != nil {
			t.Fatalf("get access token: %v", err)
		}
		if payload.ClientID != client.clientID.String() {
			t.Fatalf("ClientID = %q, want %q", payload.ClientID, client.clientID.String())
		}
		if payload.GrantType != "authorization_code" {
			t.Fatalf("GrantType = %q, want authorization_code", payload.GrantType)
		}

		accessClaims, err := env.app.TokenServices().JWT().ParseTokenClaims(tokenResp.AccessToken)
		if err != nil {
			t.Fatalf("parse access token claims: %v", err)
		}
		if accessClaims.Subject != userID {
			t.Fatalf("access token sub = %q, want %q", accessClaims.Subject, userID)
		}

		refreshClaims, err := env.app.TokenServices().JWT().ParseTokenClaims(tokenResp.RefreshToken)
		if err != nil {
			t.Fatalf("parse refresh token claims: %v", err)
		}
		if refreshClaims.Subject != userID {
			t.Fatalf("refresh token sub = %q, want %q", refreshClaims.Subject, userID)
		}

		// Step 4: tokeninfo
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?access_token="+url.QueryEscape(tokenResp.AccessToken), nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("tokeninfo status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var tokenInfo struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}
		decodeJSONBody(t, resp, &tokenInfo)
		if tokenInfo.AccessToken != tokenResp.AccessToken {
			t.Fatal("tokeninfo returned different access_token")
		}

		// Step 5: userinfo
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/userinfo", nil, bearerHeaders(tokenResp.AccessToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("userinfo status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var userInfo struct {
			Sub               string  `json:"sub"`
			PreferredUsername string  `json:"preferred_username"`
			Email             *string `json:"email"`
			Locale            *string `json:"locale"`
			ZoneInfo          *string `json:"zoneinfo"`
		}
		decodeJSONBody(t, resp, &userInfo)
		if userInfo.Sub != userID {
			t.Fatalf("sub = %q, want %q", userInfo.Sub, userID)
		}
		if userInfo.PreferredUsername != username {
			t.Fatalf("preferred_username = %q, want %q", userInfo.PreferredUsername, username)
		}
		if userInfo.Email == nil || *userInfo.Email != email {
			t.Fatalf("email = %v, want %q", userInfo.Email, email)
		}
		if userInfo.Locale == nil || *userInfo.Locale != "en-US" {
			t.Fatalf("locale = %v, want en-US", userInfo.Locale)
		}
		if userInfo.ZoneInfo == nil || *userInfo.ZoneInfo != "Europe/Paris" {
			t.Fatalf("zoneinfo = %v, want Europe/Paris", userInfo.ZoneInfo)
		}
	})

	t.Run("oidc authorization code with PKCE S256", func(t *testing.T) {
		username := "pkceuser" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-pkce", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		// Generate PKCE challenge
		codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		hasher := sha256.New()
		hasher.Write([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&code_challenge=%s&code_challenge_method=S256&state=pkce-state&nonce=pkce-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(userID),
			url.QueryEscape(codeChallenge),
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

		// Exchange with correct code_verifier
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"code":          {authResp.Code},
			"grant_type":    {"authorization_code"},
			"code_verifier": {codeVerifier},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("token exchange with PKCE status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var tokenResp struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}
		decodeJSONBody(t, resp, &tokenResp)
		if tokenResp.AccessToken == "" || tokenResp.TokenType != "Bearer" {
			t.Fatalf("unexpected token response: %+v", tokenResp)
		}
	})

	t.Run("oidc public client authorization code exchange succeeds without client_secret", func(t *testing.T) {
		username := "publicclient" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-public", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, false)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&nonce=public-client-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":  {client.clientID.String()},
			"code":       {authResp.Code},
			"grant_type": {"authorization_code"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("public client token exchange status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var tokenResp struct {
			AccessToken string `json:"access_token"`
			IdToken     string `json:"id_token"`
			TokenType   string `json:"token_type"`
		}
		decodeJSONBody(t, resp, &tokenResp)
		if tokenResp.AccessToken == "" || tokenResp.IdToken == "" || tokenResp.TokenType != "Bearer" {
			t.Fatalf("unexpected token response: %+v", tokenResp)
		}
	})

	t.Run("oidc confidential client authorization code without client_secret fails with unauthorized_client", func(t *testing.T) {
		username := "missingsecret" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-missing-secret", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&nonce=missing-secret-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":  {client.clientID.String()},
			"code":       {authResp.Code},
			"grant_type": {"authorization_code"},
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusUnauthorized, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "unauthorized_client" {
			t.Fatalf("expected error=unauthorized_client, got %v", errBody)
		}
	})

	t.Run("oidc confidential client authorization code with wrong client_secret fails with unauthorized_client", func(t *testing.T) {
		username := "wrongsecret" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-wrong-secret", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&nonce=wrong-secret-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {"wrong-secret"},
			"code":          {authResp.Code},
			"grant_type":    {"authorization_code"},
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusUnauthorized, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "unauthorized_client" {
			t.Fatalf("expected error=unauthorized_client, got %v", errBody)
		}
	})

	t.Run("oidc PKCE with wrong code_verifier fails with invalid_grant", func(t *testing.T) {
		username := "pkcefail" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-pkcefail", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		codeVerifier := "correct-verifier-value-for-test"
		hasher := sha256.New()
		hasher.Write([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&code_challenge=%s&code_challenge_method=S256&nonce=n&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
			url.QueryEscape(client.redirectURI),
			url.QueryEscape(userID),
			url.QueryEscape(codeChallenge),
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

		// Exchange with WRONG code_verifier
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"code":          {authResp.Code},
			"grant_type":    {"authorization_code"},
			"code_verifier": {"wrong-verifier-value"},
		}, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected failure for wrong code_verifier")
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_grant" {
			t.Fatalf("expected error=invalid_grant, got %v", errBody)
		}
	})

	t.Run("oidc refresh token grant issues new access token", func(t *testing.T) {
		username := "refreshuser" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-refresh", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&nonce=refresh-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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
		}
		decodeJSONBody(t, resp, &tokenResp)
		if tokenResp.RefreshToken == "" {
			t.Fatal("expected non-empty refresh_token")
		}

		// Use refresh token to get new access token
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {tokenResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("refresh token status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var refreshResp struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
		}
		decodeJSONBody(t, resp, &refreshResp)
		if refreshResp.AccessToken == "" {
			t.Fatal("expected non-empty access_token from refresh")
		}
		if refreshResp.AccessToken == tokenResp.RefreshToken {
			t.Fatal("expected refresh exchange to return a new access_token, not echo the refresh_token")
		}
		if refreshResp.AccessToken == tokenResp.AccessToken {
			t.Fatal("expected refresh exchange to issue a new access_token")
		}
		if refreshResp.TokenType != "Bearer" {
			t.Fatalf("token_type = %q, want Bearer", refreshResp.TokenType)
		}
		if refreshResp.ExpiresIn <= 0 {
			t.Fatalf("expires_in = %d, want > 0", refreshResp.ExpiresIn)
		}

		// Verify the refreshed access token payload
		payload, err := env.app.TokenServices().AccessToken().Get(refreshResp.AccessToken)
		if err != nil {
			t.Fatalf("get refreshed access token: %v", err)
		}
		if payload.GrantType != "refresh_token" {
			t.Fatalf("GrantType = %q, want refresh_token", payload.GrantType)
		}
		if payload.UserID != userID {
			t.Fatalf("UserID = %q, want %q", payload.UserID, userID)
		}
		if payload.ClientID != client.clientID.String() {
			t.Fatalf("ClientID = %q, want %q", payload.ClientID, client.clientID.String())
		}
		if len(payload.Audience) != 1 || payload.Audience[0] != client.clientID.String() {
			t.Fatalf("Audience = %v, want [%s]", payload.Audience, client.clientID.String())
		}
		if payload.Scope != "openid" {
			t.Fatalf("Scope = %q, want openid", payload.Scope)
		}
		if len(payload.Permissions) != 1 {
			t.Fatalf("Permissions = %v, want 1 permission", payload.Permissions)
		}

		claims, err := env.app.TokenServices().JWT().ParseTokenClaims(refreshResp.AccessToken)
		if err != nil {
			t.Fatalf("parse refreshed access token claims: %v", err)
		}
		if claims.Subject != userID {
			t.Fatalf("claims.Subject = %q, want %q", claims.Subject, userID)
		}
		if len(claims.Audience) != 1 || claims.Audience[0] != client.clientID.String() {
			t.Fatalf("claims.Audience = %v, want [%s]", claims.Audience, client.clientID.String())
		}

		privateClaims, err := env.app.TokenServices().JWT().ParseTokenPrivateClaims(refreshResp.AccessToken)
		if err != nil {
			t.Fatalf("parse refreshed access token private claims: %v", err)
		}
		if privateClaims.Scope != "openid" {
			t.Fatalf("privateClaims.Scope = %q, want openid", privateClaims.Scope)
		}
	})

	t.Run("oidc refresh token grant rotates refresh token and rejects reuse", func(t *testing.T) {
		username := "refreshrotate" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-refresh-rotate", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&nonce=refresh-rotate-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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
			RefreshToken string `json:"refresh_token"`
		}
		decodeJSONBody(t, resp, &tokenResp)
		if tokenResp.RefreshToken == "" {
			t.Fatal("expected non-empty refresh_token")
		}

		// First refresh: must return a NEW, rotated refresh_token.
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {tokenResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("refresh token status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var refreshResp struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		decodeJSONBody(t, resp, &refreshResp)
		if refreshResp.RefreshToken == "" {
			t.Fatal("expected refresh grant to return a rotated refresh_token")
		}
		if refreshResp.RefreshToken == tokenResp.RefreshToken {
			t.Fatal("expected rotated refresh_token to differ from the presented one")
		}

		// The rotated (new) refresh token must bind to the same user/client/consent.
		newRefreshPayload, err := env.app.TokenServices().RefreshToken().Get(refreshResp.RefreshToken)
		if err != nil {
			t.Fatalf("get rotated refresh token: %v", err)
		}
		if newRefreshPayload.UserID != userID {
			t.Fatalf("rotated refresh UserID = %q, want %q", newRefreshPayload.UserID, userID)
		}
		if newRefreshPayload.ClientID != client.clientID.String() {
			t.Fatalf("rotated refresh ClientID = %q, want %q", newRefreshPayload.ClientID, client.clientID.String())
		}

		// Reuse of the ORIGINAL (now rotated/revoked) refresh token must fail.
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {tokenResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected reuse of rotated refresh_token to fail")
		}
		var reuseErr map[string]any
		decodeJSONBody(t, resp, &reuseErr)
		if reuseErr["error"] != "invalid_grant" {
			t.Fatalf("expected error=invalid_grant for reused refresh_token, got %v", reuseErr)
		}

		// Reuse-detection defense: replaying a rotated token invalidates the
		// whole lineage, so the freshly rotated refresh token is also rejected.
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {refreshResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected lineage invalidation to reject the rotated refresh_token after reuse")
		}
		var lineageErr map[string]any
		decodeJSONBody(t, resp, &lineageErr)
		if lineageErr["error"] != "invalid_grant" {
			t.Fatalf("expected error=invalid_grant after lineage invalidation, got %v", lineageErr)
		}
	})

	t.Run("oidc refresh token rotation preserves client binding", func(t *testing.T) {
		username := "refreshrotatebind" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-refresh-rotate-bind", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		otherClient := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&nonce=refresh-rotate-bind-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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
			RefreshToken string `json:"refresh_token"`
		}
		decodeJSONBody(t, resp, &tokenResp)
		if tokenResp.RefreshToken == "" {
			t.Fatal("expected non-empty refresh_token")
		}

		// A mismatched client must be rejected AND must not rotate/consume the
		// token: the legitimate client can still use it afterwards.
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {otherClient.clientID.String()},
			"client_secret": {otherClient.secret},
			"refresh_token": {tokenResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected refresh with mismatched client to fail")
		}
		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_grant" {
			t.Fatalf("expected error=invalid_grant for mismatched client, got %v", errBody)
		}

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {tokenResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("legitimate client refresh after mismatch status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var okResp struct {
			RefreshToken string `json:"refresh_token"`
		}
		decodeJSONBody(t, resp, &okResp)
		if okResp.RefreshToken == "" || okResp.RefreshToken == tokenResp.RefreshToken {
			t.Fatalf("expected a rotated refresh_token for the legitimate client, got %q", okResp.RefreshToken)
		}
	})

	t.Run("oidc refresh token grant preserves subject from refresh token content", func(t *testing.T) {
		username := "refreshsubject" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-refresh-subject", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&nonce=refresh-subject-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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
			RefreshToken string `json:"refresh_token"`
		}
		decodeJSONBody(t, resp, &tokenResp)
		if tokenResp.RefreshToken == "" {
			t.Fatal("expected non-empty refresh_token")
		}

		refreshPayload, err := env.app.TokenServices().RefreshToken().Get(tokenResp.RefreshToken)
		if err != nil {
			t.Fatalf("get refresh token payload: %v", err)
		}
		if refreshPayload.UserID != userID {
			t.Fatalf("refresh payload UserID = %q, want %q", refreshPayload.UserID, userID)
		}

		if err := env.db.Model(&database.ApplicationConsentLog{}).
			Where("id = ?", refreshPayload.ConsentLogID).
			Update("user_id", uuid.Nil).Error; err != nil {
			t.Fatalf("zero consent log user_id: %v", err)
		}

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {tokenResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("refresh token status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var refreshResp struct {
			AccessToken string `json:"access_token"`
		}
		decodeJSONBody(t, resp, &refreshResp)
		if refreshResp.AccessToken == "" {
			t.Fatal("expected non-empty access_token from refresh")
		}

		accessPayload, err := env.app.TokenServices().AccessToken().Get(refreshResp.AccessToken)
		if err != nil {
			t.Fatalf("get refreshed access token: %v", err)
		}
		if accessPayload.UserID != userID {
			t.Fatalf("UserID = %q, want %q", accessPayload.UserID, userID)
		}

		claims, err := env.app.TokenServices().JWT().ParseTokenClaims(refreshResp.AccessToken)
		if err != nil {
			t.Fatalf("parse refreshed access token claims: %v", err)
		}
		if claims.Subject != userID {
			t.Fatalf("claims.Subject = %q, want %q", claims.Subject, userID)
		}
	})

	t.Run("oidc refresh token tokeninfo does not report refresh token as access token", func(t *testing.T) {
		username := "refreshtokeninfo" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-refresh-tokeninfo", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&nonce=refresh-tokeninfo-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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
		}
		decodeJSONBody(t, resp, &tokenResp)
		if tokenResp.RefreshToken == "" {
			t.Fatal("expected non-empty refresh_token")
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/tokeninfo?refresh_token="+url.QueryEscape(tokenResp.RefreshToken), nil, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("refresh token tokeninfo status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var tokenInfoResp struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
		}
		decodeJSONBody(t, resp, &tokenInfoResp)
		if tokenInfoResp.AccessToken != "" {
			t.Fatalf("expected empty access_token in refresh token tokeninfo response, got %q", tokenInfoResp.AccessToken)
		}
		if tokenInfoResp.RefreshToken != tokenResp.RefreshToken {
			t.Fatalf("refresh_token = %q, want %q", tokenInfoResp.RefreshToken, tokenResp.RefreshToken)
		}
		if tokenInfoResp.TokenType != "Bearer" {
			t.Fatalf("token_type = %q, want Bearer", tokenInfoResp.TokenType)
		}
		if tokenInfoResp.ExpiresIn <= 0 {
			t.Fatalf("expires_in = %d, want > 0", tokenInfoResp.ExpiresIn)
		}
	})

	t.Run("oidc authorization code cannot be reused", func(t *testing.T) {
		username := "codereuse" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-reuse", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&nonce=reuse-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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

		// First exchange succeeds
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"code":          {authResp.Code},
			"grant_type":    {"authorization_code"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("first exchange status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Second exchange with same code fails
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"code":          {authResp.Code},
			"grant_type":    {"authorization_code"},
		}, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected second code exchange to fail")
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_grant" {
			t.Fatalf("expected error=invalid_grant for reused code, got %v", errBody)
		}
	})

	t.Run("oidc online access type does not issue refresh token", func(t *testing.T) {
		username := "onlineuser" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-online", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=online&nonce=online-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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
		}
		decodeJSONBody(t, resp, &tokenResp)

		if tokenResp.AccessToken == "" {
			t.Fatal("expected non-empty access_token")
		}
		if tokenResp.RefreshToken != "" {
			t.Fatalf("expected empty refresh_token for online access, got %q", tokenResp.RefreshToken)
		}
	})

	t.Run("oidc token and consent revocation invalidates subsequent requests", func(t *testing.T) {
		username := "revokeflow" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-revoke", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")
		ensurePermissionScope(t, env, "profile")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&nonce=revoke-nonce&approve=true",
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
		}
		decodeJSONBody(t, resp, &tokenResp)

		// Userinfo works before revocation
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/userinfo", nil, bearerHeaders(tokenResp.AccessToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("userinfo before revoke status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Revoke access token
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{
			"token": {tokenResp.AccessToken},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("revoke status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Userinfo fails after revocation
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/userinfo", nil, bearerHeaders(tokenResp.AccessToken))
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected userinfo to fail after token revocation")
		}
		resp.Body.Close()

		// Revoke refresh token
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{
			"token": {tokenResp.RefreshToken},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("revoke refresh token status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Refresh fails after refresh token revocation
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {tokenResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected refresh to fail after refresh token revocation")
		}
		resp.Body.Close()
	})

	t.Run("oidc consent revocation invalidates tokens", func(t *testing.T) {
		username := "consentrev" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-consent", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&nonce=consent-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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
		}
		decodeJSONBody(t, resp, &tokenResp)

		// Revoke consent (unauthorize)
		resp = mustJSONRequest(t, env.server, http.MethodPost,
			fmt.Sprintf("/v2/apps/%s/unauthorize?user_id=%s", client.clientID.String(), url.QueryEscape(userID)),
			nil, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("unauthorize status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		// Userinfo fails after consent revocation
		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/userinfo", nil, bearerHeaders(tokenResp.AccessToken))
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected userinfo to fail after consent revocation")
		}
		resp.Body.Close()

		// Refresh fails after consent revocation
		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {tokenResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected refresh to fail after consent revocation")
		}
		resp.Body.Close()
	})

	// ==================== Device Authorization Grant ====================

	t.Run("device authorization flow issues tokens after user approval", func(t *testing.T) {
		username := "device" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-device", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, false, false)
		scope := "device.read." + uniqueSuffix()
		permID := seedPermission(t, env, scope)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/device", url.Values{
			"client_id":   {client.clientID.String()},
			"scope":       {scope},
			"access_type": {"offline"},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("device authorization status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var deviceResp struct {
			DeviceCode              string `json:"device_code"`
			UserCode                string `json:"user_code"`
			VerificationURI         string `json:"verification_uri"`
			VerificationURIComplete string `json:"verification_uri_complete"`
			ExpiresIn               int    `json:"expires_in"`
			Interval                int    `json:"interval"`
		}
		decodeJSONBody(t, resp, &deviceResp)
		if deviceResp.DeviceCode == "" || deviceResp.UserCode == "" {
			t.Fatalf("expected device and user codes, got %+v", deviceResp)
		}
		if strings.Count(deviceResp.DeviceCode, ".") == 2 {
			t.Fatalf("device_code must be opaque, got JWT-shaped value")
		}
		if deviceResp.VerificationURI != "https://accounts.example.com/auth" {
			t.Fatalf("verification_uri = %q", deviceResp.VerificationURI)
		}
		if !strings.Contains(deviceResp.VerificationURIComplete, url.QueryEscape(deviceResp.UserCode)) {
			t.Fatalf("verification_uri_complete = %q, want user code", deviceResp.VerificationURIComplete)
		}
		if deviceResp.ExpiresIn <= 0 || deviceResp.Interval != 5 {
			t.Fatalf("unexpected expiry/interval: %+v", deviceResp)
		}

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":   {client.clientID.String()},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceResp.DeviceCode},
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("pending status = %d, body=%s", resp.StatusCode, string(raw))
		}
		var pendingErr map[string]any
		decodeJSONBody(t, resp, &pendingErr)
		if pendingErr["error"] != "authorization_pending" {
			t.Fatalf("expected authorization_pending, got %v", pendingErr)
		}

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/device/authorize", url.Values{
			"user_code": {deviceResp.UserCode},
			"user_id":   {userID},
			"approve":   {"true"},
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("device approve status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":   {client.clientID.String()},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceResp.DeviceCode},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("device token status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var tokenResp struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			TokenType    string `json:"token_type"`
			Scope        string `json:"scope"`
		}
		decodeJSONBody(t, resp, &tokenResp)
		if tokenResp.AccessToken == "" || tokenResp.RefreshToken == "" || tokenResp.TokenType != "Bearer" {
			t.Fatalf("unexpected token response: %+v", tokenResp)
		}
		if tokenResp.Scope != scope {
			t.Fatalf("scope = %q, want %q", tokenResp.Scope, scope)
		}

		payload, err := env.app.TokenServices().AccessToken().Get(tokenResp.AccessToken)
		if err != nil {
			t.Fatalf("get device access token: %v", err)
		}
		if payload.UserID != userID || payload.ClientID != client.clientID.String() {
			t.Fatalf("unexpected access token payload: %+v", payload)
		}
		if payload.GrantType != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Fatalf("GrantType = %q", payload.GrantType)
		}
		if len(payload.Permissions) != 1 || payload.Permissions[0] != permID.String() {
			t.Fatalf("Permissions = %v, want [%s]", payload.Permissions, permID)
		}
	})

	t.Run("device authorization denial returns access_denied", func(t *testing.T) {
		username := "devicedeny" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-device-deny", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, false, false)
		scope := "device.deny." + uniqueSuffix()
		seedPermission(t, env, scope)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/device", url.Values{
			"client_id": {client.clientID.String()},
			"scope":     {scope},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("device authorization status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var deviceResp struct {
			DeviceCode string `json:"device_code"`
			UserCode   string `json:"user_code"`
		}
		decodeJSONBody(t, resp, &deviceResp)

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/device/authorize", url.Values{
			"user_code": {deviceResp.UserCode},
			"user_id":   {userID},
			"approve":   {"false"},
		}, bearerHeaders(sessionToken))
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("device deny status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":   {client.clientID.String()},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceResp.DeviceCode},
		}, nil)
		if resp.StatusCode != http.StatusForbidden {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("denied token status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "access_denied" {
			t.Fatalf("expected access_denied, got %v", errBody)
		}
	})

	t.Run("device authorization supports basic client authentication", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, true)
		scope := "device.basic." + uniqueSuffix()
		seedPermission(t, env, scope)

		basicAuth := base64.StdEncoding.EncodeToString(
			[]byte(client.clientID.String() + ":" + client.secret),
		)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/device", url.Values{
			"scope": {scope},
		}, map[string]string{
			"Authorization": "Basic " + basicAuth,
		})
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("device authorization status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var deviceResp struct {
			DeviceCode string `json:"device_code"`
			UserCode   string `json:"user_code"`
		}
		decodeJSONBody(t, resp, &deviceResp)
		if deviceResp.DeviceCode == "" || deviceResp.UserCode == "" {
			t.Fatalf("expected device and user codes, got %+v", deviceResp)
		}
	})

	t.Run("device authorization expired code returns expired_token", func(t *testing.T) {
		client := seedOAuthClient(t, env, false, false)
		scope := "device.expired." + uniqueSuffix()
		seedPermission(t, env, scope)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/device", url.Values{
			"client_id": {client.clientID.String()},
			"scope":     {scope},
		}, nil)
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("device authorization status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var deviceResp struct {
			DeviceCode string `json:"device_code"`
		}
		decodeJSONBody(t, resp, &deviceResp)

		manager := env.app.TokenServices().DeviceCode()
		payload, err := manager.Get(deviceResp.DeviceCode)
		if err != nil {
			t.Fatalf("get device code: %v", err)
		}
		payload.ExpiresAt = time.Now().Add(-time.Minute)
		if err := manager.Set(deviceResp.DeviceCode, payload); err != nil {
			t.Fatalf("set expired device code: %v", err)
		}

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":   {client.clientID.String()},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceResp.DeviceCode},
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("expired token status = %d, body=%s", resp.StatusCode, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "expired_token" {
			t.Fatalf("expected expired_token, got %v", errBody)
		}
	})

	// ==================== Error format tests for auth code / refresh ====================

	t.Run("oidc error: invalid authorization code returns invalid_grant", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"code":          {"invalid-code"},
			"grant_type":    {"authorization_code"},
		}, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected failure for invalid code")
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_grant" {
			t.Fatalf("expected error=invalid_grant, got %v", errBody)
		}
	})

	t.Run("oidc error: invalid refresh token returns invalid_grant", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"refresh_token": {"invalid-refresh-token"},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected failure for invalid refresh token")
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_grant" {
			t.Fatalf("expected error=invalid_grant, got %v", errBody)
		}
	})

	t.Run("oidc error: refresh token bound to another client returns invalid_grant", func(t *testing.T) {
		username := "refreshbound" + uniqueSuffix()
		email := username + "@example.com"
		userID := mustCreateUser(t, env, username, "test-password-refresh-bound", email)

		sessionToken := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, sessionToken, userID)

		client := seedOAuthClient(t, env, true, true)
		otherClient := seedOAuthClient(t, env, true, true)
		ensurePermissionScope(t, env, "openid")

		authorizeQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=code&scope=%s&redirect_uri=%s&user_id=%s&access_type=offline&nonce=refresh-client-bind-nonce&approve=true",
			client.clientID.String(),
			url.QueryEscape("openid"),
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
			RefreshToken string `json:"refresh_token"`
		}
		decodeJSONBody(t, resp, &tokenResp)
		if tokenResp.RefreshToken == "" {
			t.Fatal("expected non-empty refresh_token")
		}

		resp = mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {otherClient.clientID.String()},
			"client_secret": {otherClient.secret},
			"refresh_token": {tokenResp.RefreshToken},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected failure when refresh_token is exchanged by a different client")
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_grant" {
			t.Fatalf("expected error=invalid_grant, got %v", errBody)
		}
	})

	t.Run("oidc error: missing refresh_token parameter returns invalid_request", func(t *testing.T) {
		client := seedOAuthClient(t, env, true, true)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
			"client_id":     {client.clientID.String()},
			"client_secret": {client.secret},
			"grant_type":    {"refresh_token"},
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_request" {
			t.Fatalf("expected error=invalid_request, got %v", errBody)
		}
	})

	t.Run("oidc error: userinfo with invalid token returns invalid_token", func(t *testing.T) {
		resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/userinfo", nil, bearerHeaders("invalid-token"))
		if resp.StatusCode != http.StatusUnauthorized {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusUnauthorized, string(raw))
		}

		var errBody map[string]any
		decodeJSONBody(t, resp, &errBody)
		if errBody["error"] != "invalid_token" {
			t.Fatalf("expected error=invalid_token, got %v", errBody)
		}
	})
}
