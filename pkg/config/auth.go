package config

import "github.com/pquerna/otp/totp"

// AuthConfig groups how users sign up and authenticate.
type AuthConfig struct {
	SignIn     SignInConfig     `json:"signin"`
	SignUp     SignUpConfig     `json:"signup"`
	Phone      PhoneConfig      `json:"phone"`
	WebAuthn   WebAuthnConfig   `json:"webauthn"`
	TOTP       TOTPConfig       `json:"totp"`
	BackupCode BackupCodeConfig `json:"backupCode"`

	// DisablePublicKeys turns off publishing signing keys users marked public:
	// /{username}.keys, /{username}.gpg and the /pks/lookup key server.
	DisablePublicKeys bool `json:"disablePublicKeys"`
	// EnableKeyOwnerLookup answers GET /v2/keys?fingerprint= with the username
	// owning a public signing key. Off by default; DisablePublicKeys turns it
	// off too.
	EnableKeyOwnerLookup bool `json:"enableKeyOwnerLookup"`
}

// SignInConfig controls how users sign in. Every switch is off by default, so
// the zero value is the full built-in behavior. Logic beyond these switches,
// such as other identifiers or a policy on suspicious sign-ins, plugs in
// through pkg/auth.
type SignInConfig struct {
	// DisableUsername stops accepting a username as the sign-in identifier.
	DisableUsername bool `json:"disableUsername"`
	// DisableEmail stops accepting an email address as the sign-in identifier.
	DisableEmail bool `json:"disableEmail"`
	// RequireVerifiedEmail accepts only email addresses the user verified.
	RequireVerifiedEmail bool `json:"requireVerifiedEmail"`
	// DisablePasskey stops signing in with a passkey alone, without entering
	// an identifier first.
	DisablePasskey bool `json:"disablePasskey"`
	// DisabledMethods are authenticator types that cannot be used to sign in,
	// e.g. password, webauthn, totp, backup_code, pgp or ssh.
	DisabledMethods []string `json:"disabledMethods"`
	// RequireTwoFactor makes every sign-in pass a second factor. Users without
	// one cannot sign in.
	RequireTwoFactor bool `json:"requireTwoFactor"`
}

type WebAuthnConfig struct {
	Enabled             bool     `json:"enabled" default:"true"`
	DisplayName         string   `json:"displayName"`
	RelyingPartyID      string   `json:"relyingPartyId"`
	RelyingPartyOrigins []string `json:"relyingPartyOrigins"`
}

type TOTPConfig struct {
	Issuer string `json:"issuer"`
}

func (t *TOTPConfig) GetGenerateOpts() totp.GenerateOpts {
	return totp.GenerateOpts{
		Issuer: t.Issuer,
	}
}

const (
	defaultBackupCodeCount     = 10
	defaultBackupCodeMaxCount  = 20
	defaultBackupCodeCodeBytes = 5
)

type BackupCodeConfig struct {
	Count     int `json:"count,omitempty" default:"10"`
	MaxCount  int `json:"maxCount,omitempty" default:"20"`
	CodeBytes int `json:"codeBytes,omitempty" default:"5"`
}

func (c BackupCodeConfig) GetCount() int {
	maxCount := c.GetMaxCount()
	count := c.Count
	if c.Count <= 0 {
		count = defaultBackupCodeCount
	}
	if count > maxCount {
		return maxCount
	}
	return count
}

func (c BackupCodeConfig) GetMaxCount() int {
	if c.MaxCount <= 0 {
		return defaultBackupCodeMaxCount
	}
	return c.MaxCount
}

func (c BackupCodeConfig) GetCodeBytes() int {
	if c.CodeBytes <= 0 {
		return defaultBackupCodeCodeBytes
	}
	return c.CodeBytes
}

type PhoneConfig struct {
	// FallbackCountry is the region assumed for phone numbers given without a
	// country code.
	FallbackCountry string `json:"fallbackCountry" default:"US"`
}

type SignUpConfig struct {
	AllowSignUp bool `json:"allowSignUp" default:"true"`

	EmailRequired             bool `json:"emailRequired" default:"true"`
	EmailVerificationRequired bool `json:"emailVerificationRequired" default:"false"`
	AllowDuplicateEmail       bool `json:"allowDuplicateEmail" default:"false"`

	UsernameRequired bool `json:"usernameRequired" default:"false"`
	MaxUsernames     int  `json:"maxUsernames" default:"1"`

	PhoneRequired             bool `json:"phoneRequired" default:"false"`
	PhoneVerificationRequired bool `json:"phoneVerificationRequired" default:"false"`

	PreventDisposableEmails bool `json:"preventDisposableEmails" default:"true"`
}

const defaultOAuth2ClientSecretLength = 64

type OAuth2Config struct {
	// ConsentFrontends is the external OAuth2/OIDC consent frontend(s). It has
	// no default so that "unset" is a real state: when empty and the built-in
	// web UI is enabled, the UI serves the consent screen itself (see
	// BuildOAuth2AuthRedirectURL). Set it to use an external frontend instead.
	ConsentFrontends []string `json:"consentFrontends"`

	AllowCreate bool `json:"allowCreate" default:"true"`
	// MaxApplications caps the applications one user may own, unless an admin
	// set a cap for that user. 0 means no cap. Admins creating applications are
	// not capped.
	MaxApplications             int    `json:"maxApplications" default:"10"`
	DeviceAuthorizationEndpoint string `json:"deviceAuthorizationEndpoint"`
	ClientSecretLength          int    `json:"clientSecretLength" default:"64"`

	// DisableImplicit rejects the implicit flow (response_type token or
	// id_token), leaving the authorization code flow.
	DisableImplicit bool `json:"disableImplicit"`
	// AllowImplicitRefresh lets the implicit flow issue a refresh token for
	// access_type=offline. Off by default: tokens returned in the redirect are
	// exposed to the user agent, so they should be short-lived.
	AllowImplicitRefresh bool `json:"allowImplicitRefresh"`

	// EnablePromptBypass accepts the non-standard prompt=bypass, which lets a
	// client marked bypass_consent skip the consent screen. Off by default.
	EnablePromptBypass bool `json:"enablePromptBypass"`
}

func (c OAuth2Config) GetClientSecretLength() int {
	if c.ClientSecretLength <= 0 {
		return defaultOAuth2ClientSecretLength
	}

	return c.ClientSecretLength
}
