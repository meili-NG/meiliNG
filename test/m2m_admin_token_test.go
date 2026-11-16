package test

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	gojwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

const testAdminAudience = "https://meiling-admin.example.com"

const testOtherIssuer = "https://other-meiling.example.com"

func newM2MAdminEnv(t *testing.T, oauth2Cfg config.OAuth2Config) *featureEnv {
	t.Helper()
	return newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) {
		if oauth2Cfg.ConsentFrontends == nil {
			oauth2Cfg.ConsentFrontends = cfg.OAuth2Config.ConsentFrontends
		}
		cfg.OAuth2Config = oauth2Cfg
		cfg.AdminConfig.AdminTokenAudience = testAdminAudience
		cfg.AdminConfig.Accept = append(cfg.AdminConfig.Accept, config.AdminAcceptService)
		// Tokens from an additional accepted issuer verify, but must never
		// count as this instance's admin credential.
		cfg.TokenConfig.JWT.AcceptingIssuers = []string{testOtherIssuer}
	})
}

func requestClientCredentials(t *testing.T, env *featureEnv, client oauthClientSeed, audience string) *http.Response {
	t.Helper()
	scope := "m2m.admin." + uniqueSuffix()
	seedPermission(t, env, scope)
	return mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/token", url.Values{
		"client_id":     {client.clientID.String()},
		"client_secret": {client.secret},
		"grant_type":    {"client_credentials"},
		"scope":         {scope},
		"audience":      {audience},
	}, nil)
}

func mustClientCredentialsToken(t *testing.T, env *featureEnv, client oauthClientSeed, audience string) string {
	t.Helper()
	resp := requestClientCredentials(t, env, client, audience)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("client_credentials status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(raw))
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	decodeJSONBody(t, resp, &body)
	return body.AccessToken
}

// mustRegisterCatalogAudience registers an audience on the instance and
// returns its catalog id.
func mustRegisterCatalogAudience(t *testing.T, env *featureEnv, audience string) string {
	t.Helper()
	resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/oauth2/audiences/",
		map[string]any{"audience": audience}, adminHeaders())
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("register audience status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
	}
	var body struct {
		ID string `json:"id"`
	}
	decodeJSONBody(t, resp, &body)
	return body.ID
}

// mustAssignAudience registers an audience and assigns it to client, returning
// the assignment id.
func mustAssignAudience(t *testing.T, env *featureEnv, client oauthClientSeed, audience string) string {
	t.Helper()
	audienceID := mustRegisterCatalogAudience(t, env, audience)
	resp := mustJSONRequest(t, env.server, http.MethodPost,
		"/v2/apps/"+client.clientID.String()+"/oauth2/audiences/",
		map[string]any{"audience_id": audienceID}, adminHeaders())
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("assign audience status = %d, want %d, body=%s", resp.StatusCode, http.StatusCreated, string(raw))
	}
	var body struct {
		ID string `json:"id"`
	}
	decodeJSONBody(t, resp, &body)
	return body.ID
}

// adminStatus calls an admin-only endpoint with token as a bearer credential.
func adminStatus(t *testing.T, env *featureEnv, token string) (int, string) {
	t.Helper()
	resp := mustJSONRequest(t, env.server, http.MethodGet, "/v2/permissions/", nil, bearerHeaders(token))
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(raw)
}

// forgeAccessToken signs an access token with the instance key,
// copying claims from base and applying edit. It is never written to the
// token store unless it reuses the jti of a stored token.
func forgeAccessToken(t *testing.T, env *featureEnv, base string, edit func(*gojwt.Claims)) string {
	t.Helper()

	cfg := env.app.Config()
	jwtManager := env.app.TokenServices().JWT()
	claims, err := jwtManager.ParseTokenClaims(base)
	if err != nil {
		t.Fatalf("ParseTokenClaims: %v", err)
	}
	edit(claims)

	signer := tokens.NewJWTManager(&config.MeilingConfig{
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:      cfg.TokenConfig.JWT.Algorithm,
			Issuer:         claims.Issuer,
			PrivateKeyPath: cfg.TokenConfig.JWT.PrivateKeyPath,
			PublicKeyPath:  cfg.TokenConfig.JWT.PublicKeyPath,
		}},
	})
	signed := signer.GetClaims()
	signed.Claims = *claims
	token, err := signer.GenerateTokenWithPrivateClaims(signed, tokens.JWTGlobalPrivateClaims{
		TokenType: tokens.TokenTypeAccessToken,
		GrantType: "client_credentials",
	})
	if err != nil {
		t.Fatalf("GenerateTokenWithPrivateClaims: %v", err)
	}
	return token
}

func TestM2MAdminAccessToken(t *testing.T) {
	t.Run("an issued token with the registered admin audience is admin", func(t *testing.T) {
		env := newM2MAdminEnv(t, config.OAuth2Config{})
		client := seedOAuthClient(t, env, false, true)
		mustAssignAudience(t, env, client, testAdminAudience)

		token := mustClientCredentialsToken(t, env, client, testAdminAudience)
		if status, body := adminStatus(t, env, token); status != http.StatusOK {
			t.Fatalf("admin status = %d, want %d, body=%s", status, http.StatusOK, body)
		}
	})

	t.Run("a token for another audience is not admin", func(t *testing.T) {
		env := newM2MAdminEnv(t, config.OAuth2Config{})
		client := seedOAuthClient(t, env, false, true)
		mustAssignAudience(t, env, client, testAdminAudience)
		mustAssignAudience(t, env, client, "https://orders.example.com")

		token := mustClientCredentialsToken(t, env, client, "https://orders.example.com")
		if status, body := adminStatus(t, env, token); status == http.StatusOK {
			t.Fatalf("admin status = %d for a token of another audience, body=%s", status, body)
		}
	})

	t.Run("without service in admin.accept the token is not admin", func(t *testing.T) {
		env := newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) {
			cfg.AdminConfig.AdminTokenAudience = testAdminAudience
		})
		client := seedOAuthClient(t, env, false, true)
		mustAssignAudience(t, env, client, testAdminAudience)

		token := mustClientCredentialsToken(t, env, client, testAdminAudience)
		if status, body := adminStatus(t, env, token); status == http.StatusOK {
			t.Fatalf("admin status = %d with service not accepted, body=%s", status, body)
		}
	})

	t.Run("a token signed with the key but never issued is rejected", func(t *testing.T) {
		env := newM2MAdminEnv(t, config.OAuth2Config{})
		client := seedOAuthClient(t, env, false, true)
		mustAssignAudience(t, env, client, testAdminAudience)
		issued := mustClientCredentialsToken(t, env, client, testAdminAudience)

		forged := forgeAccessToken(t, env, issued, func(c *gojwt.Claims) {
			c.ID = "00000000-0000-4000-8000-000000000001"
		})
		if status, body := adminStatus(t, env, forged); status != http.StatusUnauthorized {
			t.Fatalf("forged token status = %d, want %d, body=%s", status, http.StatusUnauthorized, body)
		}
	})

	t.Run("an expired token is rejected even though it is still stored", func(t *testing.T) {
		env := newM2MAdminEnv(t, config.OAuth2Config{})
		client := seedOAuthClient(t, env, false, true)
		mustAssignAudience(t, env, client, testAdminAudience)
		issued := mustClientCredentialsToken(t, env, client, testAdminAudience)

		expired := forgeAccessToken(t, env, issued, func(c *gojwt.Claims) {
			c.Expiry = gojwt.NewNumericDate(time.Now().Add(-time.Hour))
		})
		status, body := adminStatus(t, env, expired)
		if status != http.StatusUnauthorized || !strings.Contains(body, "expired") {
			t.Fatalf("expired token status = %d, body=%s, want 401 expired", status, body)
		}
	})

	t.Run("a token from an accepting issuer is not admin", func(t *testing.T) {
		env := newM2MAdminEnv(t, config.OAuth2Config{})
		client := seedOAuthClient(t, env, false, true)
		mustAssignAudience(t, env, client, testAdminAudience)
		issued := mustClientCredentialsToken(t, env, client, testAdminAudience)

		foreign := forgeAccessToken(t, env, issued, func(c *gojwt.Claims) {
			c.Issuer = testOtherIssuer
		})
		if _, err := env.app.TokenServices().JWT().ParseTokenClaims(foreign); err != nil {
			t.Fatalf("the accepting issuer should verify: %v", err)
		}
		if status, body := adminStatus(t, env, foreign); status != http.StatusUnauthorized {
			t.Fatalf("foreign issuer status = %d, want %d, body=%s", status, http.StatusUnauthorized, body)
		}
	})

	t.Run("a revoked token is rejected", func(t *testing.T) {
		env := newM2MAdminEnv(t, config.OAuth2Config{})
		client := seedOAuthClient(t, env, false, true)
		mustAssignAudience(t, env, client, testAdminAudience)
		token := mustClientCredentialsToken(t, env, client, testAdminAudience)

		resp := mustFormRequest(t, env.server, http.MethodPost, "/v2/oauth2/revoke", url.Values{"token": {token}}, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke status = %d", resp.StatusCode)
		}

		if status, body := adminStatus(t, env, token); status != http.StatusUnauthorized {
			t.Fatalf("revoked token status = %d, want %d, body=%s", status, http.StatusUnauthorized, body)
		}
	})
}

func TestClientCredentialsAudienceRestriction(t *testing.T) {
	t.Run("an audience the client was not given is refused", func(t *testing.T) {
		env := newM2MAdminEnv(t, config.OAuth2Config{})
		client := seedOAuthClient(t, env, false, true)

		for _, audience := range []string{testAdminAudience, "https://unregistered.example.com", "https://api.example.com https://unregistered.example.com"} {
			resp := requestClientCredentials(t, env, client, audience)
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_target") {
				t.Fatalf("audience %q: status = %d, body=%s, want 400 invalid_target", audience, resp.StatusCode, string(raw))
			}
		}
	})

	t.Run("admins assign and unassign a registered audience, and unassigning takes effect", func(t *testing.T) {
		env := newM2MAdminEnv(t, config.OAuth2Config{})
		client := seedOAuthClient(t, env, false, true)
		const audience = "https://billing.example.com"
		id := mustAssignAudience(t, env, client, audience)
		mustClientCredentialsToken(t, env, client, audience)

		path := "/v2/apps/" + client.clientID.String() + "/oauth2/audiences/"
		resp := mustJSONRequest(t, env.server, http.MethodGet, path, nil, adminHeaders())
		var listed []struct {
			ID         string `json:"id"`
			AudienceID string `json:"audience_id"`
			Audience   string `json:"audience"`
		}
		decodeJSONBody(t, resp, &listed)
		found := ""
		for _, item := range listed {
			if item.ID == id && item.Audience == audience {
				found = item.AudienceID
			}
		}
		if found == "" {
			t.Fatalf("listed audiences %#v do not include %q", listed, audience)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, path, map[string]any{"audience_id": found}, adminHeaders())
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("duplicate assignment status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}

		resp = mustJSONRequest(t, env.server, http.MethodPost, path,
			map[string]any{"audience_id": "6c0d2f5e-0b5a-4a8e-9a1e-2c4f6b8d0e12"}, adminHeaders())
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unregistered audience assignment status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}

		resp = mustJSONRequest(t, env.server, http.MethodDelete, path+"?audienceId="+id, nil, adminHeaders())
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unassign audience status = %d", resp.StatusCode)
		}
		resp = requestClientCredentials(t, env, client, audience)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("unassigned audience status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("the audience catalog is registered once and reused across clients", func(t *testing.T) {
		env := newM2MAdminEnv(t, config.OAuth2Config{})
		const audience = "https://shared.example.com"
		audienceID := mustRegisterCatalogAudience(t, env, audience)

		resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/oauth2/audiences/",
			map[string]any{"audience": audience}, adminHeaders())
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("duplicate catalog entry status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/oauth2/audiences/",
			map[string]any{"audience": "two words"}, adminHeaders())
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("whitespace catalog entry status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}

		first := seedOAuthClient(t, env, false, true)
		second := seedOAuthClient(t, env, false, true)
		for _, client := range []oauthClientSeed{first, second} {
			resp = mustJSONRequest(t, env.server, http.MethodPost,
				"/v2/apps/"+client.clientID.String()+"/oauth2/audiences/",
				map[string]any{"audience_id": audienceID}, adminHeaders())
			resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("assign shared audience status = %d", resp.StatusCode)
			}
			mustClientCredentialsToken(t, env, client, audience)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/audiences/"+audienceID+"/clients", nil, adminHeaders())
		var clients []struct {
			ClientID string `json:"client_id"`
		}
		decodeJSONBody(t, resp, &clients)
		if len(clients) != 2 {
			t.Fatalf("audience clients = %#v, want 2", clients)
		}

		resp = mustJSONRequest(t, env.server, http.MethodDelete, "/v2/oauth2/audiences/"+audienceID+"/", nil, adminHeaders())
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("delete assigned audience status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}

		resp = mustJSONRequest(t, env.server, http.MethodGet, "/v2/oauth2/audiences/", nil, adminHeaders())
		var catalog []struct {
			ID          string `json:"id"`
			Audience    string `json:"audience"`
			ClientCount int64  `json:"client_count"`
		}
		decodeJSONBody(t, resp, &catalog)
		for _, entry := range catalog {
			if entry.ID == audienceID && entry.ClientCount != 2 {
				t.Fatalf("catalog entry %#v client_count = %d, want 2", entry, entry.ClientCount)
			}
		}
	})

	t.Run("only admins manage audiences", func(t *testing.T) {
		env := newM2MAdminEnv(t, config.OAuth2Config{})
		client := seedOAuthClient(t, env, false, true)
		username := "audowner" + uniqueSuffix()
		userID := mustCreateUser(t, env, username, "test-password-audience", username+"@example.com")
		session := mustCreateSessionToken(t, env)
		mustAttachUserToSession(t, env, session, userID)
		if err := env.db.Exec("UPDATE applications SET owner_id = ? WHERE id = ?", userID, client.clientID).Error; err != nil {
			t.Fatalf("set owner: %v", err)
		}

		path := fmt.Sprintf("/v2/apps/%s/oauth2/audiences/?user_id=%s", client.clientID, userID)
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			resp := mustJSONRequest(t, env.server, method, path, map[string]any{"audience_id": testAdminAudience}, bearerHeaders(session))
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
				t.Fatalf("owner %s audiences status = %d, want 401/403", method, resp.StatusCode)
			}
		}

		catalogPath := "/v2/oauth2/audiences/?user_id=" + userID
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			resp := mustJSONRequest(t, env.server, method, catalogPath,
				map[string]any{"audience": "https://owner.example.com"}, bearerHeaders(session))
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
				t.Fatalf("owner %s catalog status = %d, want 401/403", method, resp.StatusCode)
			}
		}
	})
}
