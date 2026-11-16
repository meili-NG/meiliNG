package database

import (
	"log"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"gorm.io/gorm"
)

// Permission embeds PermissionFields from internal/models.
// This is intended to be a generic layer of permission
// for both oAuth2 scope and LDAP.
type Permission struct {
	models.PermissionFields `gorm:"embedded"`
}

func (p *Permission) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}

	return nil
}

func (p *Permission) GetLocalizedMessages() map[string]any {
	if p.LocalizedMessagesJSON == "" {
		return nil
	}

	var res map[string]any
	err := jsoniter.ConfigFastest.UnmarshalFromString(p.LocalizedMessagesJSON, &res)
	if err != nil {
		log.Printf("database: unmarshal localized messages of permission %s: %v", p.ID, err)
		return nil
	}

	return res
}

func (p *Permission) Serialize() types.PermissionSerialized {
	serialized := utils.TransferData[Permission, types.PermissionSerialized](*p)
	serialized.LocalizedMessages = p.GetLocalizedMessages()

	return serialized
}
