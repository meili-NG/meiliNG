package models

import "github.com/google/uuid"

// PermissionFields contains permission-related fields.
type PermissionFields struct {
	ID                    uuid.UUID `gorm:"column:id;type:UUID;primary_key" json:"id"`
	Scope                 string    `gorm:"column:scope;not null;unique;index" json:"scope"`
	Message               string    `gorm:"column:message" json:"message"`
	LocalizedMessagesJSON string    `gorm:"column:localized_messages;type:JSON" json:"-"`
	IsPublic              bool      `gorm:"column:is_public;not null;default:false" json:"isPublic"`
	// IsDefault allows the permission to every application created afterwards; existing applications keep their own set.
	IsDefault bool `gorm:"column:is_default;not null;default:false" json:"isDefault"`
	// ParentID is the permission that contains this one; NULL means top level.
	ParentID uuid.NullUUID `gorm:"column:parent_id;type:UUID" json:"parentId"`
	// Metadata is free-form data plugins and distributions keep on the record;
	// core never reads it. Only admins change it over the API.
	Metadata map[string]any `gorm:"column:metadata;type:JSON;serializer:json" json:"-"`
}
