package models

import (
	"github.com/google/uuid"
)

// OAuthClientFields contains what an application needs to speak OAuth2 and
// OpenID Connect. An application has at most one.
type OAuthClientFields struct {
	ApplicationID uuid.UUID `gorm:"column:application_id;type:UUID;primary_key" json:"applicationId"`
	// IsPublicClient marks the client as a public client (RFC 6749 §2.1): it may
	// complete the authorization_code flow without a client_secret. It can
	// still own secrets for confidential-only grants such as client_credentials
	// (M2M), so the secret never needs to ship to a public frontend.
	IsPublicClient bool `gorm:"column:is_public;not null;default:false" json:"isPublicClient"`
	BypassConsent  bool `gorm:"column:bypass_consent;not null;default:false" json:"-"`
	// BackchannelLogoutURI receives an OIDC back-channel logout token when a
	// user who signed into the client through a session signs out of it.
	// Empty turns back-channel logout off for the client.
	BackchannelLogoutURI string `gorm:"column:backchannel_logout_uri" json:"backchannelLogoutUri,omitempty"`
	// FrontchannelLogoutURI is loaded in the browser, with iss and sid, when
	// such a user signs out. Empty turns front-channel logout off.
	FrontchannelLogoutURI string `gorm:"column:frontchannel_logout_uri" json:"frontchannelLogoutUri,omitempty"`
}

// OAuthPostLogoutRedirectURIFields is a URI the client may send the browser
// back to after an RP-initiated logout.
type OAuthPostLogoutRedirectURIFields struct {
	ID       uuid.UUID `gorm:"column:id;type:UUID;primary_key" json:"id"`
	URI      string    `gorm:"column:uri;not null" json:"uri"`
	ClientID uuid.UUID `gorm:"column:client_id;type:UUID;not null;index" json:"clientId"`
}

// ApplicationSessionFields records that a user of a session signed into an
// application, so logging the user out of the session can tell it.
type ApplicationSessionFields struct {
	ID            uuid.UUID `gorm:"column:id;type:UUID;primary_key" json:"id"`
	SessionID     string    `gorm:"column:session_id;not null;uniqueIndex:idx_application_session" json:"sessionId"`
	UserID        uuid.UUID `gorm:"column:user_id;type:UUID;not null;uniqueIndex:idx_application_session" json:"userId"`
	ApplicationID uuid.UUID `gorm:"column:application_id;type:UUID;not null;uniqueIndex:idx_application_session" json:"applicationId"`
}

// OAuthRedirectURIFields contains redirect URI fields.
type OAuthRedirectURIFields struct {
	ID       uuid.UUID `gorm:"column:id;type:UUID;primary_key" json:"id"`
	URI      string    `gorm:"column:uri;not null" json:"redirect_uri"`
	ClientID uuid.UUID `gorm:"column:client_id;type:UUID;not null" json:"clientId"`
}

// OAuthAudienceFields is one audience registered on this instance: a resource
// server a machine client can be granted access to. Only admins manage these,
// because an audience is what a resource server, and with the admin token
// audience Meiling itself, accepts a token for.
type OAuthAudienceFields struct {
	ID          uuid.UUID `gorm:"column:id;type:UUID;primary_key" json:"id"`
	Audience    string    `gorm:"column:audience;not null;uniqueIndex" json:"audience"`
	Description string    `gorm:"column:description;not null;default:''" json:"description"`
	// Metadata is free-form data plugins and distributions keep on the record;
	// core never reads it. Only admins change it over the API.
	Metadata map[string]any `gorm:"column:metadata;type:JSON;serializer:json" json:"-"`
}

// OAuthClientAudienceFields assigns a registered audience to a client, making
// it requestable with the client_credentials grant.
type OAuthClientAudienceFields struct {
	ID         uuid.UUID `gorm:"column:id;type:UUID;primary_key" json:"id"`
	ClientID   uuid.UUID `gorm:"column:client_id;type:UUID;not null;uniqueIndex:idx_oauth_client_audience" json:"clientId"`
	AudienceID uuid.UUID `gorm:"column:audience_id;type:UUID;not null;uniqueIndex:idx_oauth_client_audience" json:"audienceId"`
}

// OAuthCredentialFields contains client credential fields.
type OAuthCredentialFields struct {
	ID       uuid.UUID `gorm:"column:id;type:UUID;primary_key" json:"id"`
	Secret   string    `gorm:"column:secret;not null" json:"client_secret"`
	ClientID uuid.UUID `gorm:"column:client_id;type:UUID;not null" json:"clientId"`
	Notes    string    `gorm:"column:notes" json:"notes,omitempty"`
}
