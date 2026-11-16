package models

import (
	"time"

	"github.com/google/uuid"
)

// UserFields contains the core user fields shared between DB and DTO layers.
// Both GORM and JSON tags are included - GORM uses gorm tags, JSON encoder uses json tags.
type UserFields struct {
	ID               uuid.UUID      `gorm:"column:id;type:UUID;primary_key" json:"id"`
	Data             map[string]any `gorm:"column:data;type:JSON;serializer:json;not null" json:"-"`
	TwoFactorEnabled bool           `gorm:"column:2fa_enabled;not null" json:"twoFactorEnabled"`
	// MaxApplications overrides oauth2.maxApplications for this user when set.
	MaxApplications *int       `gorm:"column:max_applications" json:"maxApplications,omitempty"`
	DeletedAt       *time.Time `gorm:"column:deleted_at" json:"deletedAt,omitempty"`
}

// UserNameFields contains username-related fields.
type UserNameFields struct {
	Username string    `gorm:"column:username;not null;unique;primary_key" json:"username"`
	UserID   uuid.UUID `gorm:"column:user_id;index" json:"userId"`
}

// UserEmailFields contains email-related fields.
type UserEmailFields struct {
	ID        uuid.UUID `gorm:"column:id;type:UUID;primary_key" json:"id"`
	Email     string    `gorm:"column:email;not null;index" json:"email"`
	Verified  bool      `gorm:"column:verified;not null" json:"verified"`
	UserID    uuid.UUID `gorm:"column:user_id;type:UUID;not null" json:"userId"`
	IsPrimary bool      `gorm:"column:is_primary;default:false" json:"isPrimary"`
}

// UserPhoneFields contains phone-related fields.
type UserPhoneFields struct {
	ID        uuid.UUID `gorm:"column:id;type:UUID;primary_key" json:"id"`
	Phone     string    `gorm:"column:phone;not null" json:"phone"`
	Verified  bool      `gorm:"column:verified;not null" json:"verified"`
	UserID    uuid.UUID `gorm:"column:user_id;type:UUID;not null" json:"userId"`
	IsPrimary bool      `gorm:"column:is_primary;default:false" json:"isPrimary"`
}

// UserDataFields contains user profile data fields.
type UserDataFields struct {
	Name          string         `gorm:"column:name" json:"name,omitempty"`
	DisplayName   string         `gorm:"column:display_name" json:"displayName,omitempty"`
	Birthday      *time.Time     `gorm:"column:birthday" json:"birthday,omitempty"`
	AvatarUrl     *string        `gorm:"column:avatar_url" json:"avatarUrl,omitempty"`
	Language      *string        `gorm:"column:language" json:"language,omitempty"`
	Timezone      *string        `gorm:"column:timezone" json:"timezone,omitempty"`
	Metadata      map[string]any `gorm:"column:data;type:JSON;not null;serializer:json" json:"-"`
	FirstName     string         `gorm:"column:first_name" json:"firstName,omitempty"`
	MiddleName    *string        `gorm:"column:middle_name" json:"middleName,omitempty"`
	LastName      string         `gorm:"column:last_name" json:"lastName,omitempty"`
	ExtraData     map[string]any `gorm:"column:extra_data;type:JSON;not null;serializer:json" json:"-"`
	UserDataLocks map[string]any `gorm:"column:user_data_locks;type:JSON;not null;serializer:json" json:"-"`
	UserID        uuid.UUID      `gorm:"primaryKey;column:user_id;type:UUID;not null" json:"-"`
}
