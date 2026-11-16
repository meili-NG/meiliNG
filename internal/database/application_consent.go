package database

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func GetConsentLogDB() (*gorm.DB, error) {
	return GetDatabaseWithPreload("Permissions", "Application", "User")
}

func GetUserIDTokenFromConsentLogDB() (*gorm.DB, error) {
	return GetDatabaseWithPreload("Permissions", "Application", "User", "User.Emails", "User.Phones", "User.UserNames", "User.UserData")
}

type ApplicationConsentLog struct {
	ID uuid.UUID `gorm:"column:id;type:UUID;primary_key"`

	Application   Application `gorm:"foreignKey:ApplicationID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	ApplicationID uuid.UUID   `gorm:"column:application_id;type:UUID;not null"`

	User   User      `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	UserID uuid.UUID `gorm:"column:user_id;type:UUID;not null"`

	ConsentedAt time.Time  `gorm:"column:consented_at;not null"`
	RevokedAt   *time.Time `gorm:"column:revoked_at"`

	Permissions []Permission `gorm:"many2many:application_consent_logs_permissions;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
	ConsentIP   string       `gorm:"column:consent_ip"`
}

func (l *ApplicationConsentLog) BeforeCreate(tx *gorm.DB) error {
	if l.ID == uuid.Nil {
		l.ID = uuid.New()
	}
	return nil
}

func (l *ApplicationConsentLog) HasPhonePermissions() bool {
	return l.HasPermissionScope("phone")
}

func (l *ApplicationConsentLog) HasEmailPermissions() bool {
	return l.HasPermissionScope("email")
}

func (l *ApplicationConsentLog) HasProfilePermissions() bool {
	return l.HasPermissionScope("profile")
}

func (l *ApplicationConsentLog) HasPermissionScope(scope string) bool {
	for _, p := range l.Permissions {
		if p.Scope == scope {
			return true
		}
	}

	// Not granted by name: an ancestor grant still counts.
	tree, err := LoadPermissionTree()
	return err == nil && tree.CoversScope(l.Permissions, scope)
}

func (l *ApplicationConsentLog) Revoke() error {
	db, err := GetDatabase()
	if err != nil {
		return err
	}

	now := time.Now()
	l.RevokedAt = &now
	err = db.Save(l).Error
	if err != nil {
		return err
	}

	return nil
}

func (l *ApplicationConsentLog) IsRevoked() bool {
	return l.RevokedAt != nil && l.RevokedAt.Before(time.Now())
}
