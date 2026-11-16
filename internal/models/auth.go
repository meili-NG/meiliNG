package models

import (
	"time"

	"github.com/google/uuid"
)

// UserAuthenticatorFields contains authenticator fields.
type UserAuthenticatorFields struct {
	ID                uuid.UUID      `gorm:"column:id;type:UUID;primary_key" json:"id"`
	Type              string         `gorm:"column:type;not null" json:"type"`
	Data              map[string]any `gorm:"column:data;type:JSON;not null;serializer:json" json:"-"`
	Identifier        *string        `gorm:"column:identifier;index" json:"-"`
	UserID            uuid.UUID      `gorm:"column:user_id;type:UUID;not null" json:"userId"`
	AllowSignIn       bool           `gorm:"column:allow_sign_in;not null" json:"allowSignIn"`
	Allow2FA          bool           `gorm:"column:allow_2fa;not null" json:"allow2FA"`
	AllowPasswordless bool           `gorm:"column:allow_passwordless;not null" json:"allowPasswordless"`
	Note              string         `gorm:"column:note" json:"note"`
}

// SignInLogFields contains sign-in log fields.
type SignInLogFields struct {
	ID          uuid.UUID      `gorm:"column:id;type:UUID;primary_key" json:"id"`
	SessionID   uuid.UUID      `gorm:"column:session_id;type:UUID" json:"sessionId"`
	UserID      uuid.UUID      `gorm:"column:user_id;type:UUID;not null" json:"userId"`
	SignedInAt  time.Time      `gorm:"column:signed_in_at;not null" json:"signedInAt"`
	ExpiresAt   *time.Time     `gorm:"column:expires_at" json:"expiresAt,omitempty"`
	SignedOutAt *time.Time     `gorm:"column:signed_out_at" json:"signedOutAt,omitempty"`
	IP          string         `gorm:"column:ip" json:"ip"`
	Country     string         `gorm:"column:country" json:"country,omitempty"`
	GeoIPData   map[string]any `gorm:"column:geoip_data;type:JSON;serializer:json" json:"geoipData,omitempty"`
	UserAgent   string         `gorm:"column:user_agent" json:"userAgent"`
}
