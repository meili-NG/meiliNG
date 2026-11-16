package test

import (
	"fmt"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

type implicitFixture struct {
	client       oauthClientSeed
	userID       string
	sessionToken string
}

func newImplicitFixture(t *testing.T, env *featureEnv) implicitFixture {
	t.Helper()

	username := "implicit" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "test-password-implicit", username+"@example.com")
	sessionToken := mustCreateSessionToken(t, env)
	mustAttachUserToSession(t, env, sessionToken, userID)
	ensurePermissionScope(t, env, "openid")

	return implicitFixture{
		client:       seedOAuthClient(t, env, true, true),
		userID:       userID,
		sessionToken: sessionToken,
	}
}

func (f implicitFixture) authorize(t *testing.T, env *featureEnv, responseType string, accessType string) *http.Response {
	t.Helper()

	query := fmt.Sprintf(
		"/v2/apps/%s/oauth2/auth/?response_type=%s&scope=openid&redirect_uri=%s&user_id=%s&access_type=%s&nonce=implicit-nonce&approve=true",
		f.client.clientID.String(),
		responseType,
		url.QueryEscape(f.client.redirectURI),
		url.QueryEscape(f.userID),
		accessType,
	)
	return mustJSONRequest(t, env.server, http.MethodPost, query, nil, bearerHeaders(f.sessionToken))
}

type implicitAuthorizeResponse struct {
	Code   string `json:"code"`
	Tokens *struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	} `json:"tokens"`
}

func mustAuthorizeImplicit(t *testing.T, env *featureEnv, f implicitFixture, accessType string) implicitAuthorizeResponse {
	t.Helper()

	resp := f.authorize(t, env, "token", accessType)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("implicit authorize status = %d, body=%s", resp.StatusCode, string(raw))
	}

	var body implicitAuthorizeResponse
	decodeJSONBody(t, resp, &body)
	if body.Tokens == nil || body.Tokens.AccessToken == "" {
		t.Fatal("expected an access token from the implicit flow")
	}
	return body
}

func assertUnsupportedResponseType(t *testing.T, resp *http.Response) {
	t.Helper()

	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, string(raw))
	}
	if !strings.Contains(string(raw), "unsupported_response_type") {
		t.Fatalf("body = %s, want unsupported_response_type", string(raw))
	}
}

func TestOAuth2ImplicitFlowConfig(t *testing.T) {
	t.Run("implicit flow omits the refresh token by default", func(t *testing.T) {
		env := newFeatureEnv(t)
		f := newImplicitFixture(t, env)

		body := mustAuthorizeImplicit(t, env, f, "offline")
		if body.Tokens.RefreshToken != "" {
			t.Fatal("implicit flow issued a refresh token without oauth2.allowImplicitRefresh")
		}
	})

	t.Run("allowImplicitRefresh issues a refresh token for offline access", func(t *testing.T) {
		env := newFeatureEnvWithOAuth2Config(t, config.OAuth2Config{AllowImplicitRefresh: true})
		f := newImplicitFixture(t, env)

		body := mustAuthorizeImplicit(t, env, f, "offline")
		if body.Tokens.RefreshToken == "" {
			t.Fatal("expected a refresh token with oauth2.allowImplicitRefresh")
		}

		online := mustAuthorizeImplicit(t, env, f, "online")
		if online.Tokens.RefreshToken != "" {
			t.Fatal("online access must not issue a refresh token")
		}
	})

	t.Run("disableImplicit rejects token response type but keeps the code flow", func(t *testing.T) {
		env := newFeatureEnvWithOAuth2Config(t, config.OAuth2Config{DisableImplicit: true})
		f := newImplicitFixture(t, env)

		assertUnsupportedResponseType(t, f.authorize(t, env, "token", "online"))

		consentQuery := fmt.Sprintf(
			"/v2/apps/%s/oauth2/auth/?response_type=token&scope=openid&redirect_uri=%s&user_id=%s",
			f.client.clientID.String(),
			url.QueryEscape(f.client.redirectURI),
			url.QueryEscape(f.userID),
		)
		assertUnsupportedResponseType(t, mustJSONRequest(t, env.server, http.MethodGet, consentQuery, nil, bearerHeaders(f.sessionToken)))

		redirectQuery := fmt.Sprintf(
			"/v2/oauth2/auth?client_id=%s&response_type=token&scope=openid&redirect_uri=%s",
			f.client.clientID.String(),
			url.QueryEscape(f.client.redirectURI),
		)
		assertUnsupportedResponseType(t, mustJSONRequest(t, env.server, http.MethodGet, redirectQuery, nil, nil))

		resp := f.authorize(t, env, "code", "online")
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("code flow status = %d, body=%s", resp.StatusCode, string(raw))
		}
		resp.Body.Close()
	})

	// response_type=id_token is rejected by the HTTP layer's enum, so this
	// drives the service directly to pin the ordering: a missing nonce must be
	// rejected before a consent log is written.
	t.Run("id_token without nonce is rejected before a consent log is issued", func(t *testing.T) {
		env := newFeatureEnv(t)
		f := newImplicitFixture(t, env)

		session, err := env.app.TokenServices().Session().Get(f.sessionToken)
		if err != nil {
			t.Fatalf("session get: %v", err)
		}

		countLogs := func() int64 {
			var n int64
			if err := env.db.Model(&database.ApplicationConsentLog{}).
				Where("application_id = ? AND user_id = ?", f.client.clientID, f.userID).
				Count(&n).Error; err != nil {
				t.Fatalf("count consent logs: %v", err)
			}
			return n
		}
		before := countLogs()

		_, err = api.AuthorizeOAuth2Client(api.OAuth2AuthRequest{
			Config:        env.app.Config(),
			TokenServices: env.app.TokenServices(),
			Caller:        tokens.SessionPrincipal(&session),
			ClientID:      f.client.clientID.String(),
			UserID:        f.userID,
			ResponseType:  "id_token",
			RedirectURI:   f.client.redirectURI,
			Scope:         "openid",
			Approve:       true,
		})
		if err == nil || !strings.Contains(err.Error(), "nonce") {
			t.Fatalf("error = %v, want the missing nonce to be rejected", err)
		}
		if after := countLogs(); after != before {
			t.Fatalf("consent logs = %d, want %d: a rejected request must not issue a log", after, before)
		}
	})
}
