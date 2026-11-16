package types

import (
	"encoding/json"
	"net/mail"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/common"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// Captcha types

// CaptchaRequest carries a bot challenge response; see pkg/captcha.
type CaptchaRequest struct {
	CaptchaToken string `json:"captchaToken" validate:"optional" required:"false" example:"ey..." doc:"Challenge response from the enabled captcha provider"`
}

// User types

type PaginatedUserSerialized = PaginatedResponse[UserSerialized]
type PaginatedSigninLogSerialized = PaginatedResponse[SignInLogSerialized]

type UserSerialized struct {
	ID               string              `json:"id" example:"12345678-90ab-cdef-0123-4567890abcdef"`
	Usernames        []string            `json:"usernames" example:"username1,username2"`
	Emails           []string            `json:"emails" example:"test1@example.com,test2@example.com"`
	Phones           []string            `json:"phones" example:"+12025550123,+12025550124"`
	TwoFactorEnabled bool                `json:"twoFactorEnabled" example:"true"`
	MaxApplications  *int                `json:"maxApplications,omitempty" doc:"This user's cap on owned applications, when an admin set one"`
	UserData         *SerializedUserData `json:"userData,omitempty"`
	DeletedAt        *time.Time          `json:"deletedAt,omitempty" example:"2006-01-02T15:04:05Z"`
}

type CreateUserRequest struct {
	Username string            `json:"username" validate:"optional" required:"false"`
	Password string            `json:"password" validate:"required"`
	Emails   []AddEmailRequest `json:"emails" validate:"optional" required:"false"`
	Phones   []AddPhoneRequest `json:"phones" validate:"optional" required:"false"`
}

type BulkCheckUsersRequest struct {
	UserIDs []string `json:"userIds" validate:"required" example:"12345678-90ab-cdef-0123-4567890abcdef,abcdef01-2345-6789-abcd-ef0123456789"`
}

type BulkCheckUsersResponse struct {
	Users    []UserSerialized `json:"users"`
	NotFound []string         `json:"notFound" example:"12345678-90ab-cdef-0123-4567890abcdef"`
}

type ChangePasswordRequest struct {
	PreviousPassword string `json:"prevPassword" validate:"required"`
	NewPassword      string `json:"newPassword" validate:"required"`
}

type AddUsernameRequest struct {
	Username string `json:"username" example:"username"`
}

type AddEmailRequest struct {
	UpdateEmailRequest
	Email string `json:"email" example:"test1@example.com"`
}

type UpdateEmailRequest struct {
	Verified bool `json:"verified" example:"true" validate:"optional" required:"false"`
}

type AddPhoneRequest struct {
	UpdatePhoneRequest
	Phone string `json:"phone" example:"+12025550123"`
}

type UpdatePhoneRequest struct {
	Verified bool `json:"verified" example:"true" validate:"optional" required:"false"`
}

type UpdateUserDataRequest struct {
	Name       *string `json:"name,omitempty" example:"John Doe"`
	FirstName  *string `json:"firstName,omitempty" example:"John"`
	MiddleName *string `json:"middleName,omitempty" example:"Smith"`
	LastName   *string `json:"lastName,omitempty" example:"Doe"`

	DisplayName *string    `json:"displayName,omitempty" example:"John Doe"`
	Birthday    *time.Time `json:"birthday,omitempty" example:"2006-01-02T15:04:05Z"`
	Language    *string    `json:"language,omitempty" nullable:"true" example:"en"`
	Timezone    *string    `json:"timezone,omitempty" nullable:"true" example:"Etc/UTC"`

	LanguageSet bool `json:"-"`
	TimezoneSet bool `json:"-"`
}

func (r *UpdateUserDataRequest) UnmarshalJSON(data []byte) error {
	type updateUserDataRequest UpdateUserDataRequest

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	var decoded updateUserDataRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*r = UpdateUserDataRequest(decoded)
	_, r.LanguageSet = raw["language"]
	_, r.TimezoneSet = raw["timezone"]
	return nil
}

type SerializedUserData struct {
	Name       string `json:"name,omitempty" example:"John Doe"`
	FirstName  string `json:"firstName,omitempty" example:"John"`
	MiddleName string `json:"middleName,omitempty" example:"Smith"`
	LastName   string `json:"lastName,omitempty" example:"Doe"`

	DisplayName string     `json:"displayName,omitempty" example:"John Doe"`
	Birthday    *time.Time `json:"birthday,omitempty" example:"2006-01-02T15:04:05Z"`
	Language    *string    `json:"language,omitempty" example:"en"`
	Timezone    *string    `json:"timezone,omitempty" example:"Etc/UTC"`
}

type VerifyEmailRequest struct {
	VerificationToken string `json:"verificationToken" example:"ey..." validate:"optional" required:"false"`
	Challenge         string `json:"challenge" example:"ey..." validate:"optional" required:"false"`
}

type VerifyEmailResponse struct {
	VerificationToken string `json:"verificationToken,omitempty" example:"ey..."`
}

type AddTOTPRequest struct {
	Note      string `json:"note,omitempty" required:"false" example:"My TOTP"`
	Challenge string `json:"challenge,omitempty" required:"false" example:"123456"`
	Token     string `json:"token,omitempty" required:"false" example:"ey..."`
}

type AddTOTPResponse struct {
	TotpUrl string `json:"totpUrl" example:"otpauth://totp/Meiling:..."`
	Token   string `json:"token" example:"ey..."`
}

type GetTOTPResponse struct {
	ID   string `json:"id" example:"12345678-90ab-cdef-0123-4567890abcdef"`
	Note string `json:"note" example:"My TOTP"`
}

// AddSigningKeyRequest registers an OpenPGP or SSH public key for sign-in.
type AddSigningKeyRequest struct {
	Key  string `json:"key" doc:"Armored OpenPGP public key, or an SSH public key in authorized_keys form" example:"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host"`
	Note string `json:"note,omitempty" required:"false" example:"Laptop"`
	// Public publishes the key; it is off unless set.
	Public bool `json:"public,omitempty" required:"false" doc:"Publish the key at /{username}.keys or /{username}.gpg and on /pks/lookup"`
}

// UpdateSigningKeyRequest changes a signing key's note or whether it is public.
type UpdateSigningKeyRequest struct {
	Note   *string `json:"note,omitempty" required:"false" example:"Laptop"`
	Public *bool   `json:"public,omitempty" required:"false"`
}

// SigningKeyResponse describes a registered signing key.
type SigningKeyResponse struct {
	ID          string `json:"id" example:"12345678-90ab-cdef-0123-4567890abcdef"`
	Note        string `json:"note" example:"Laptop"`
	Fingerprint string `json:"fingerprint" example:"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"`
	Public      bool   `json:"public"`
}

type GetBackupCodesResponse struct {
	Remaining int `json:"remaining" example:"8"`
}

type RegenerateBackupCodesResponse struct {
	Codes     []string `json:"codes" example:"ABCD-2345,EFGH-6789"`
	Remaining int      `json:"remaining" example:"10"`
}

type GetWebAuthnResponse struct {
	ID   string `json:"id" example:"12345678-90ab-cdef-0123-4567890abcdef"`
	Note string `json:"note" example:"My WebAuthn"`
}

type UpdateUserRequest struct {
	TwoFactorEnabled *bool `json:"twoFactorEnabled,omitempty" example:"true"`
	// MaxApplications is admin only.
	MaxApplications *int `json:"maxApplications,omitempty" doc:"Admin only. Applications this user may own: 0 for no cap, a negative value to fall back to oauth2.maxApplications" example:"20"`
}

type AddWebAuthnRequest struct {
	Token    string         `json:"token,omitempty" required:"false" example:"ey..."`
	Response map[string]any `json:"response,omitempty" required:"false"`
	Note     string         `json:"note,omitempty" required:"false" example:"My WebAuthn"`
}

type AddWebAuthnResponse struct {
	Token    string                                       `json:"token,omitempty" example:"ey..."`
	Response *protocol.PublicKeyCredentialCreationOptions `json:"response,omitempty"`
}

type SignInLogSerialized struct {
	ID          string         `json:"id" example:"12345678-90ab-cdef-0123-4567890abcdef"`
	IP          string         `json:"ip" example:"127.0.0.1"`
	Country     string         `json:"country,omitempty" example:"Canada"`
	CountryCode string         `json:"countryCode,omitempty" example:"CA"`
	GeoIPData   map[string]any `json:"geoipData,omitempty"`
	SignedInAt  time.Time      `json:"signedInAt" example:"2006-01-02T15:04:05Z"`
	ExpiresAt   *time.Time     `json:"expiresAt,omitempty" example:"2006-01-03T15:04:05Z"`
	SignedOutAt *time.Time     `json:"signedOutAt,omitempty" example:"2006-01-02T15:04:05Z"`
	UserAgent   string         `json:"userAgent" example:"Mozilla/5.0"`
}

type SignInCountryStatisticSerialized struct {
	Country     string `json:"country,omitempty" example:"Germany"`
	CountryCode string `json:"countryCode,omitempty" example:"DE"`
	Count       int64  `json:"count" example:"42"`
}

type SignInStatisticsSerialized struct {
	Countries []SignInCountryStatisticSerialized `json:"countries"`
}

type SignInStatisticsResponse struct {
	Statistics SignInStatisticsSerialized `json:"statistics"`
}

// Permission types

type PaginatedPermissionSerialized = PaginatedResponse[PermissionSerialized]

type PermissionSerialized struct {
	ID                string         `json:"id" example:"12345678-90ab-cdef-0123-4567890abcdef"`
	Scope             string         `json:"scope" example:"openid"`
	Message           string         `json:"message" example:"Access User Information"`
	LocalizedMessages map[string]any `json:"localizedMessages"`
	IsPublic          bool           `json:"isPublic" example:"true"`
	IsDefault         bool           `json:"isDefault" example:"false" doc:"New applications start allowed this permission. Existing applications are not changed"`
	ParentID          uuid.NullUUID  `json:"parentId" nullable:"true" format:"uuid" doc:"Permission that contains this one; null for a top level permission"`
}

type AddPermissionRequest struct {
	Scope     string `json:"scope" example:"openid" validate:"required"`
	IsPublic  bool   `json:"isPublic" example:"true" validate:"optional" required:"false"`
	IsDefault bool   `json:"isDefault" example:"false" validate:"optional" required:"false"`
	ParentID  string `json:"parentId" validate:"optional" required:"false" doc:"Permission that contains the new one; omit for a top level permission"`
	Message   string `json:"message" validate:"optional" required:"false"`
}

// UpdatePermissionRequest replaces every mutable field of a permission; scope is immutable.
type UpdatePermissionRequest struct {
	ParentID  string `json:"parentId" doc:"Permission that contains this one; empty string for a top level permission"`
	IsPublic  bool   `json:"isPublic"`
	IsDefault bool   `json:"isDefault"`
	Message   string `json:"message"`
}

// Challenge types

type ChallengeActionType string

const ChallengeAction ChallengeActionType = "challenge"
const OwnershipAction ChallengeActionType = "ownership"

type ChallengeIssuedPayload struct {
	Challenge string `json:"challenge,omitempty"`
	ExpiresIn int64  `json:"expires_in,omitempty"`
}

type ChallengeSuccessPayload struct {
	Passed bool `json:"passed"`
}

type ChallengeResponsePayload struct {
	Response string `json:"response" validate:"optional" required:"false"`
}

type ChallengeRequest struct {
	Action         ChallengeActionType `json:"action"`
	ChallengeToken string              `json:"requestToken"`
	OwnershipCheck *OwnershipCheck     `json:"ownershipCheck,omitempty"`
}

type OwnershipCheck struct {
	Phones []string `json:"phones"`
	Emails []string `json:"emails"`
}

// SignIn types

type SignInRequest struct {
	ID       string `json:"id" example:"00000000-0000-0000-0000-000000000000" validate:"optional" required:"false"`
	Username string `json:"username" example:"username" validate:"optional" required:"false"`

	// WebAuthn Flow
	UseWebAuthn bool `json:"useWebAuthn" example:"true" validate:"optional" required:"false"`

	// Challenges
	ChallengeToken string `json:"challengeToken" example:"token" validate:"optional" required:"false"`

	// For ownership verification
	OwnershipToken string `json:"ownershipToken" example:"token" validate:"optional" required:"false"`
}

type SignInChallenges struct {
	Tokens []string `json:"challengeResponses" example:"token1,token2"`
}

// SignUp types

type SignUpTokenRequest struct {
	CaptchaRequest

	Email string `json:"email" validate:"optional" required:"false" example:"test@example.com"`
	Phone string `json:"phone" validate:"optional" required:"false" example:"+12025550123"`

	OwnershipToken string `json:"ownershipToken" validate:"optional" required:"false" example:"ey..."`
	Response       string `json:"response" validate:"optional" required:"false" example:"ey..."`
}

type SignUpTokenResponse struct {
	Token string `json:"token" example:"ey..."`
}

type SignUpRequest struct {
	Email          string `json:"email" validate:"optional" required:"false" example:"test@example.com"`
	Phone          string `json:"phone" validate:"optional" required:"false" example:"+12025550123"`
	OwnershipToken string `json:"ownershipToken" validate:"optional" required:"false" example:"ey..."`
	Username       string `json:"username" validate:"optional" required:"false" example:"username"`
	Password       string `json:"password" validate:"required" example:"password"`
	Name           string `json:"name" validate:"optional" required:"false" example:"Name"`
}

func (r *SignUpRequest) GetEmail(tokenServices *tokens.Services) string {
	email := r.Email

	payload := r.GetVerificationPayload(tokenServices)
	if payload != nil && payload.Email != "" {
		return payload.Email
	}

	if _, err := mail.ParseAddress(email); err == nil {
		return email
	}

	return ""
}

func (r *SignUpRequest) GetPhone(tokenServices *tokens.Services) string {
	phone := r.Phone

	payload := r.GetVerificationPayload(tokenServices)
	if payload != nil && payload.Phone != "" {
		phone = payload.Phone
	}

	return phone
}

func (r *SignUpRequest) GetVerificationPayload(tokenServices *tokens.Services) *tokens.VerificationMergedPayload {
	if tokenServices == nil {
		return nil
	}

	tokenManager := tokenServices.Verification()
	payload, err := tokenManager.Get(r.OwnershipToken)
	if err != nil {
		return nil
	}

	return payload
}

func (r *SignUpRequest) IsEmailVerified(tokenServices *tokens.Services) bool {
	payload := r.GetVerificationPayload(tokenServices)
	if payload == nil {
		return false
	}

	if payload.Email != "" {
		return true
	}

	return false
}

func (r *SignUpRequest) IsPhoneVerified(tokenServices *tokens.Services) bool {
	payload := r.GetVerificationPayload(tokenServices)
	if payload == nil {
		return false
	}

	if payload.Phone != "" {
		return true
	}

	return false
}

func (r *SignUpRequest) ValidateConfigCompliance(tokenServices *tokens.Services, config *config.SignUpConfig) error {
	email := r.GetEmail(tokenServices)
	if email == "" && config.EmailRequired {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "email address is required")
	} else if config.EmailVerificationRequired {
		if !r.IsEmailVerified(tokenServices) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "email address is not verified")
		}
	} else if config.PreventDisposableEmails {
		if common.IsDisposableEmail(email) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "email address is disposable")
		}
	}

	phone := r.GetPhone(tokenServices)
	if phone == "" && config.PhoneRequired {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "phone number is required")
	} else if config.PhoneVerificationRequired {
		if !r.IsPhoneVerified(tokenServices) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "phone number is not verified")
		}
	}

	if config.UsernameRequired && r.Username == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "username is required")
	}

	if r.Username != "" && !validator.IsValidUsername(r.Username) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "username is invalid")
	}

	if r.Password == "" && !validator.IsValidPassword(r.Password) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "password is required or too short")
	}

	return nil
}

type SignUpConfigSerialized struct {
	AllowSignUp               bool `json:"allowSignup"`
	EmailRequired             bool `json:"emailRequired"`
	EmailVerificationRequired bool `json:"emailVerificationRequired"`
	UsernameRequired          bool `json:"usernameRequired"`
	PhoneRequired             bool `json:"phoneRequired"`
	PhoneVerificationRequired bool `json:"phoneVerificationRequired"`
}

func (s *SignUpConfigSerialized) LoadConfig(config *config.SignUpConfig) {
	s.AllowSignUp = config.AllowSignUp
	s.EmailRequired = config.EmailRequired
	s.EmailVerificationRequired = config.EmailVerificationRequired
	s.UsernameRequired = config.UsernameRequired
	s.PhoneRequired = config.PhoneRequired
	s.PhoneVerificationRequired = config.PhoneVerificationRequired
}

// IForgot types

type IForgotRequest struct {
	OwnershipToken string `json:"ownership_token" validate:"required"`
	Username       string `json:"username" validate:"required"`
	Password       string `json:"password" validate:"required"`
}

type IForgotResponse struct {
}

// Application types

type PaginatedSerializedApplication = PaginatedResponse[SerializedApplication]

type SerializedApplication struct {
	ID             string `json:"id" sanitizer:"user,owner"`
	IconURL        string `json:"iconUrl" sanitizer:"user,owner"`
	Name           string `json:"name" sanitizer:"user,owner"`
	Terms          string `json:"terms" sanitizer:"user,owner"`
	Privacy        string `json:"privacy" sanitizer:"user,owner"`
	OwnerID        string `json:"ownerId,omitempty" sanitizer:"owner"`
	IsVerified     bool   `json:"isVerified" sanitizer:"user,owner"`
	IsPublicClient bool   `json:"isPublicClient" sanitizer:"user,owner"`
}

type CreateApplicationPayload struct {
	Name           string   `json:"name" validate:"required"`
	RedirectURIs   []string `json:"redirectURIs" validate:"optional" required:"false" example:"https://example.com/oauth2/callback"`
	Privacy        string   `json:"privacy" validate:"required" example:"https://example.com/privacy"`
	Terms          string   `json:"terms" validate:"required" example:"https://example.com/terms"`
	IsPublicClient *bool    `json:"isPublicClient" validate:"optional" required:"false"`
}

// OAuth2 types

type UserConsentRequest struct {
	UserConsentRequired bool `json:"userConsentRequired"`
	// Permissions lists what the user is asked to grant: requested permissions not
	// already granted, with those contained in another listed permission left out.
	Permissions []PermissionSerialized `json:"permissions"`
	// ReauthenticationRequired is set when the user has to sign in again first,
	// for max_age or acr_values; authorizing before that is refused.
	ReauthenticationRequired bool `json:"reauthenticationRequired,omitempty"`
}

type AuthorizeResponse struct {
	Code   string         `json:"code,omitempty" example:"ey..."`
	Tokens *TokenResponse `json:"tokens,omitempty"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token" example:"ey..."`
	RefreshToken string `json:"refresh_token,omitempty" example:"ey..."`
	TokenType    string `json:"token_type" example:"Bearer"`
	ExpiresIn    int    `json:"expires_in" example:"3600"`
	Scope        string `json:"scope,omitempty" example:"profile openid..."`
	ImpliedScope string `json:"implied_scope,omitempty" example:"profile openid..." doc:"Token introspection only: scope plus every scope it contains"`
	IdToken      string `json:"id_token,omitempty" example:"ey..."`
	// Subject and Audience are set by token info for an ID token.
	Subject  string   `json:"sub,omitempty" doc:"Token info of an ID token only: the user"`
	Audience []string `json:"aud,omitempty" doc:"Token info of an ID token only: the client it was issued to"`
}

type TokenRequest struct {
	ClientID     string `json:"client_id" form:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" form:"client_secret" validate:"optional" required:"false"`
	Code         string `json:"code" form:"code" validate:"optional" required:"false" example:"ey..."`
	DeviceCode   string `json:"device_code" form:"device_code" validate:"optional" required:"false" example:"ey..."`
	RefreshToken string `json:"refresh_token" form:"refresh_token" validate:"optional" required:"false" example:"ey..."`
	GrantType    string `json:"grant_type" form:"grant_type" validate:"required" enums:"authorization_code,refresh_token,client_credentials,urn:ietf:params:oauth:grant-type:device_code"`
	Scope        string `json:"scope" form:"scope" validate:"optional" required:"false" example:"profile openid..."`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri" validate:"optional" required:"false" example:"https://example.com/oauth2/callback"`
	CodeVerifier string `json:"code_verifier" form:"code_verifier" validate:"optional" required:"false" example:"verifier_content"`
	Audience     string `json:"audience" form:"audience" validate:"optional" required:"false" example:"https://api.example.com"`
}

type DeviceAuthorizationRequest struct {
	ClientID     string `json:"client_id" form:"client_id" validate:"optional" required:"false" example:"00000000-0000-0000-0000-000000000000"`
	ClientSecret string `json:"client_secret" form:"client_secret" validate:"optional" required:"false"`
	Scope        string `json:"scope" form:"scope" validate:"optional" required:"false" example:"profile openid"`
	AccessType   string `json:"access_type" form:"access_type" validate:"optional" required:"false" enums:"offline,online"`
}

type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code" example:"ey..."`
	UserCode                string `json:"user_code" example:"ABCD-2345"`
	VerificationURI         string `json:"verification_uri" example:"https://accounts.example.com/auth/device"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty" example:"https://accounts.example.com/auth/device?user_code=ABCD-2345"`
	ExpiresIn               int    `json:"expires_in" example:"900"`
	Interval                int    `json:"interval" example:"5"`
}

type DeviceAuthorizeRequest struct {
	UserCode string `json:"user_code" form:"user_code" validate:"required" example:"ABCD-2345"`
	UserID   string `json:"user_id" form:"user_id" validate:"required" example:"00000000-0000-0000-0000-000000000000"`
	Approve  string `json:"approve" form:"approve" validate:"required" required:"true" example:"true"`
}

type ClientSecretSerialized struct {
	ID           string `json:"id"`
	ClientSecret string `json:"client_secret"`
	Notes        string `json:"notes,omitempty"`
}

type AddRedirectUriRequest struct {
	RedirectURI string `json:"redirect_uri" validate:"required"`
}

type AssignClientAudienceRequest struct {
	AudienceID string `json:"audience_id" validate:"required" example:"6c0d2f5e-0b5a-4a8e-9a1e-2c4f6b8d0e12"`
}

type ClientAudienceSerialized struct {
	ID          string `json:"id"`
	AudienceID  string `json:"audience_id"`
	Audience    string `json:"audience"`
	Description string `json:"description"`
}

// ApplicationPermissionLimitSerialized is what an application may request.
// While limited is false the application may request any permission and
// permissions is not applied. Default permissions are always requestable and
// are not listed here.
type ApplicationPermissionLimitSerialized struct {
	Limited     bool                   `json:"limited" doc:"Whether the application may only request the default permissions, the listed permissions and the ones they contain"`
	Permissions []PermissionSerialized `json:"permissions"`
}

type SetApplicationPermissionLimitRequest struct {
	Limited       bool     `json:"limited" doc:"Restrict the application to the default permissions plus permissionIds"`
	PermissionIDs []string `json:"permissionIds" doc:"Permissions the application may request; each one also allows the permissions it contains"`
}

type CreateAudienceRequest struct {
	Audience    string `json:"audience" validate:"required" example:"https://api.example.com"`
	Description string `json:"description" validate:"optional" required:"false"`
}

type UpdateAudienceRequest struct {
	Description *string `json:"description" validate:"optional" required:"false"`
}

type AudienceSerialized struct {
	ID          string `json:"id"`
	Audience    string `json:"audience"`
	Description string `json:"description"`
	ClientCount int64  `json:"client_count"`
}

type AudienceClientSerialized struct {
	ID         string `json:"id"`
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
}

type ClientRedirectUriSerialized struct {
	ID          string `json:"id"`
	RedirectURI string `json:"redirect_uri"`
}

// IntrospectTokenRequest is an RFC 7662 token introspection request. The
// client authenticates with HTTP Basic or client_id and client_secret.
type IntrospectTokenRequest struct {
	Token         string `json:"token" form:"token" validate:"required"`
	TokenTypeHint string `json:"token_type_hint" form:"token_type_hint" validate:"optional" required:"false" enums:"access_token,refresh_token"`
	ClientID      string `json:"client_id" form:"client_id" validate:"optional" required:"false"`
	ClientSecret  string `json:"client_secret" form:"client_secret" validate:"optional" required:"false"`
}

// IntrospectionResponse is an RFC 7662 token introspection response. Only
// active is set for a token that is invalid or not the caller's to inspect.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	TokenType string   `json:"token_type,omitempty" enum:"access_token,refresh_token"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Jti       string   `json:"jti,omitempty"`
}

type RevokeTokenRequest struct {
	Token         string `json:"token" form:"token" validate:"required"`
	TokenTypeHint string `json:"token_type_hint" form:"token_type_hint" validate:"optional" required:"false" enums:"access_token,refresh_token"`
}

type UpdateApplicationPayload struct {
	Name           string `json:"name" validate:"optional" required:"false"`
	IsPublicClient *bool  `json:"isPublicClient" validate:"optional" required:"false"`
}

type CreateClientSecretRequest struct {
	Notes string `json:"notes" validate:"optional" required:"false"`
}

// ClientLogoutSettings are an OAuth2 client's OpenID Connect logout settings.
// An empty URI turns that kind of logout off for the client.
type ClientLogoutSettings struct {
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris" doc:"Where an RP-initiated logout may return to, matched exactly"`
	BackchannelLogoutURI   string   `json:"backchannelLogoutUri" doc:"Receives a logout token when a user signs out; empty for none" required:"false"`
	FrontchannelLogoutURI  string   `json:"frontchannelLogoutUri" doc:"Loaded in the browser, with iss and sid, when a user signs out; empty for none" required:"false"`
}
