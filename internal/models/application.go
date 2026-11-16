package models

import (
	"github.com/google/uuid"
)

// ApplicationFields contains the protocol-neutral fields of an application: a
// relying party registered on this instance. Its ID is the OAuth2 client_id.
// Note: Application also carries CreatedAt/UpdatedAt/DeletedAt.
type ApplicationFields struct {
	ID         uuid.UUID  `gorm:"column:id;type:UUID;primary_key" json:"id"`
	IconURL    string     `gorm:"column:icon_url;not null" json:"iconUrl"`
	Name       string     `gorm:"column:name;not null" json:"name"`
	OwnerID    *uuid.UUID `gorm:"column:owner_id;type:UUID" json:"ownerId,omitempty"`
	IsVerified bool       `gorm:"column:is_verified;not null;default:false" json:"isVerified"`
	// AllowAnyPermission lifts the per-application permission limit; unset means limited, so a row written by any path fails closed.
	AllowAnyPermission bool `gorm:"column:allow_any_permission;not null;default:false" json:"-"`
	// Metadata is free-form data plugins and distributions keep on the record;
	// core never reads it. Only admins change it over the API.
	Metadata map[string]any `gorm:"column:metadata;type:JSON;serializer:json" json:"-"`
}

// ApplicationPermissionFields allows an application to request a permission,
// and everything under it, unless the application's AllowAnyPermission is set.
type ApplicationPermissionFields struct {
	ApplicationID uuid.UUID `gorm:"column:application_id;type:UUID;primary_key" json:"applicationId"`
	PermissionID  uuid.UUID `gorm:"column:permission_id;type:UUID;primary_key" json:"permissionId"`
}
