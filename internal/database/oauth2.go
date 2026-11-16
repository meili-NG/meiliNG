package database

import (
	"crypto/subtle"
	"net"
	"net/url"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"gorm.io/gorm"
)

// isValidOAuth2URI checks if a URI is a valid OAuth2 redirect URI
func isValidOAuth2URI(uri string) bool {
	deps := GetDependencies()
	if deps == nil || deps.IsValidOAuth2URI == nil {
		return false
	}
	return deps.IsValidOAuth2URI(uri)
}

func GetOAuth2DB() (*gorm.DB, error) {
	return GetDatabaseWithPreload([]string{
		"Application",
		"RedirectURIs",
		"PostLogoutRedirectURIs",
		"Audiences",
		"Audiences.Audience",
		"Credentials",
	}...)
}

// OauthClient embeds OAuthClientFields from internal/models. It is the OAuth2
// and OpenID Connect part of an application, keyed by the application's ID.
type OauthClient struct {
	models.OAuthClientFields `gorm:"embedded"`

	// Relations
	Application  *Application       `gorm:"foreignKey:ApplicationID;references:ID"`
	RedirectURIs []OauthRedirectURI `gorm:"foreignKey:ClientID;references:ApplicationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	// PostLogoutRedirectURIs are where an RP-initiated logout may return to.
	PostLogoutRedirectURIs []OauthPostLogoutRedirectURI `gorm:"foreignKey:ClientID;references:ApplicationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Audiences              []OauthClientAudience        `gorm:"foreignKey:ClientID;references:ApplicationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Credentials            []OauthCredential            `gorm:"foreignKey:ClientID;references:ApplicationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (c *OauthClient) GetClientSecrets() []string {
	return utils.Filter(utils.Map(c.Credentials, func(credential OauthCredential) string {
		return credential.Secret
	}), func(secret string) bool {
		return secret != ""
	})
}

// HasCredentials reports whether the client owns at least one stored secret.
func (c *OauthClient) HasCredentials() bool {
	return len(c.Credentials) > 0
}

// RequireClientSecret reports whether the client must authenticate with a
// stored secret for grants that allow public clients to skip authentication
// (authorization_code, refresh_token, device_code).
//
// The IsPublicClient flag is the sole source of truth: a client is confidential
// unless its owner explicitly marks it public. A public client may still own
// secrets for confidential-only grants such as client_credentials (M2M), so the
// secret never has to ship to a public frontend.
func (c *OauthClient) RequireClientSecret() bool {
	return !c.IsPublicClient
}

// matchesClientSecret reports whether secret matches one of the client's
// stored secrets, using a constant-time comparison. It performs no public-client
// bypass: callers that allow secretless authentication must check that
// separately.
func (c *OauthClient) matchesClientSecret(secret string) bool {
	for _, credential := range c.Credentials {
		if subtle.ConstantTimeCompare([]byte(credential.Secret), []byte(secret)) == 1 {
			return true
		}
	}
	return false
}

func (c *OauthClient) GetRedirectURIs() []string {
	return utils.Map(c.RedirectURIs, func(uri OauthRedirectURI) string {
		return uri.URI
	})
}

func (c *OauthClient) AddRedirectURI(uri string) {
	redirectUri := OauthRedirectURI{
		OAuthRedirectURIFields: models.OAuthRedirectURIFields{
			ID:       uuid.New(),
			URI:      uri,
			ClientID: c.ApplicationID,
		},
	}

	db, err := GetDatabase()
	if err != nil {
		return
	}

	db.Create(&redirectUri)
	c.RedirectURIs = append(c.RedirectURIs, redirectUri)
}

// GetAudiences returns the audiences assigned to the client, which are the
// ones it may request with the client_credentials grant.
func (c *OauthClient) GetAudiences() []string {
	audiences := make([]string, 0, len(c.Audiences))
	for _, assigned := range c.Audiences {
		if assigned.Audience != nil {
			audiences = append(audiences, assigned.Audience.Audience)
		}
	}
	return audiences
}

// AllowsAudience reports whether audience is assigned to the client. The match
// is exact: audiences are opaque identifiers, not URLs to normalize.
func (c *OauthClient) AllowsAudience(audience string) bool {
	for _, assigned := range c.Audiences {
		if assigned.Audience != nil && assigned.Audience.Audience == audience {
			return true
		}
	}
	return false
}

func (c *OauthClient) ValidateRedirectURI(target string) bool {
	var targetParsed *url.URL

	for _, redirectURI := range c.RedirectURIs {
		// check if the redirectURI is ietf oauth2 uri

		uri := redirectURI.URI
		if isValidOAuth2URI(uri) {
			if target == uri {
				return true
			}
		} else {
			parsed, err := url.Parse(uri)
			if err != nil {
				continue
			}

			if targetParsed == nil {
				targetParsed, err = url.Parse(target)
				if err != nil {
					continue
				}
			}

			// Case folding would match a non-ASCII host to a registered ASCII one that browsers resolve elsewhere.
			if strings.IndexFunc(targetParsed.Host, func(r rune) bool { return r > unicode.MaxASCII }) >= 0 {
				continue
			}

			// A loopback redirect for a native app matches on any port (RFC 8252
			// §7.3): the app binds whatever port is free when it starts, so it cannot
			// register one in advance.
			if matchesLoopbackRedirect(parsed, targetParsed) {
				return true
			}

			// following should be same:
			// - scheme
			// - host
			// - port
			// - path

			if utils.ComparePreprocessedArgs(parsed, targetParsed, func(a any) any {
				if v, ok := a.(string); ok {
					return strings.ToLower(v)
				}

				return a
			}, "Scheme", "Host", "Path") && parsed.Port() == targetParsed.Port() {
				return true
			}
		}
	}

	return false
}

// matchesLoopbackRedirect reports whether target matches a registered loopback
// redirect URI, ignoring the port as RFC 8252 §7.3 requires: "The authorization server
// MUST allow any port to be specified at the time of the request for loopback IP
// redirect URIs." It applies only to an http URI naming a loopback IP literal
// (127.0.0.1, [::1]); "localhost" is not one (§8.3), and every other URI keeps exact
// matching. Scheme, host and path must still match.
func matchesLoopbackRedirect(registered, target *url.URL) bool {
	if !strings.EqualFold(registered.Scheme, "http") || !strings.EqualFold(target.Scheme, "http") {
		return false
	}
	ip := net.ParseIP(registered.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	targetIP := net.ParseIP(target.Hostname())
	if targetIP == nil || !ip.Equal(targetIP) {
		return false
	}
	return registered.Path == target.Path
}

func (c *OauthClient) AddClientSecret(secret string) error {
	if c.ValidateClientSecret(secret) {
		return nil
	}

	db, err := GetDatabase()
	if err != nil {
		return err
	}

	credential := OauthCredential{
		OAuthCredentialFields: models.OAuthCredentialFields{
			ID:       uuid.New(),
			Secret:   secret,
			ClientID: c.ApplicationID,
		},
	}
	db.Create(&credential)

	c.Credentials = append(c.Credentials, credential)
	return nil
}

// ValidateClientSecret validates client authentication for grants that permit
// public clients to authenticate without a secret (authorization_code,
// refresh_token, device_code).
//
// Behavior:
//   - Public client, empty secret: allowed (no authentication required).
//   - Public client, non-empty secret: the secret must still be valid if
//     supplied, so a wrong secret is rejected rather than silently ignored.
//   - Confidential client: the secret must match.
func (c *OauthClient) ValidateClientSecret(secret string) bool {
	if c.IsPublicClient {
		if secret == "" {
			return true
		}
		// A public client that owns secrets may present one; if it does, it
		// must be correct. A public client with no secrets rejects any provided
		// secret.
		return c.matchesClientSecret(secret)
	}

	return c.matchesClientSecret(secret)
}

// ValidateConfidentialClientSecret validates client authentication for grants
// that require a confidential client (e.g. client_credentials / M2M). It always
// requires a valid, non-empty secret regardless of the public flag.
func (c *OauthClient) ValidateConfidentialClientSecret(secret string) bool {
	if secret == "" || !c.HasCredentials() {
		return false
	}
	return c.matchesClientSecret(secret)
}

func (c *OauthClient) IssueAuthorization(u *User, perms []Permission) *OauthAuthorization {
	auth := OauthAuthorization{
		client:      c,
		user:        u,
		permissions: perms,
	}

	return &auth
}

// OauthCredential embeds OAuthCredentialFields from internal/models.
type OauthCredential struct {
	models.OAuthCredentialFields `gorm:"embedded"`
}

// OauthAudience embeds OAuthAudienceFields from internal/models.
type OauthAudience struct {
	models.OAuthAudienceFields `gorm:"embedded"`
}

// OauthClientAudience embeds OAuthClientAudienceFields from internal/models.
type OauthClientAudience struct {
	models.OAuthClientAudienceFields `gorm:"embedded"`

	Audience *OauthAudience `gorm:"foreignKey:AudienceID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (a *OauthAudience) BeforeCreate(tx *gorm.DB) error {
	if a.OAuthAudienceFields.ID == uuid.Nil {
		a.OAuthAudienceFields.ID = uuid.New()
	}
	return nil
}

func (a *OauthClientAudience) BeforeCreate(tx *gorm.DB) error {
	if a.OAuthClientAudienceFields.ID == uuid.Nil {
		a.OAuthClientAudienceFields.ID = uuid.New()
	}
	return nil
}

// OauthRedirectURI embeds OAuthRedirectURIFields from internal/models.
type OauthRedirectURI struct {
	models.OAuthRedirectURIFields `gorm:"embedded"`
}

type OauthPostLogoutRedirectURI struct {
	models.OAuthPostLogoutRedirectURIFields `gorm:"embedded"`
}

// ApplicationSession records a user of a session signing into an
// application; see models.ApplicationSessionFields.
type ApplicationSession struct {
	models.ApplicationSessionFields `gorm:"embedded"`
}
