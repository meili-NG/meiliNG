package database

import (
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"gorm.io/gorm"
)

func GetApplicationDB() (*gorm.DB, error) {
	return GetDatabaseWithPreload("OauthClient", "Policies")
}

// Application embeds ApplicationFields from internal/models. It is the
// protocol-neutral record of a relying party; what a protocol needs hangs off
// it as a separate relation.
type Application struct {
	CreatedAt                time.Time      `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt                time.Time      `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt                gorm.DeletedAt `gorm:"column:deleted_at;index"`
	models.ApplicationFields `gorm:"embedded"`

	// Relations
	OauthClient *OauthClient        `gorm:"foreignKey:ApplicationID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Policies    []ApplicationPolicy `gorm:"foreignKey:ApplicationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (a *Application) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}

func (a *Application) Serialize(flags ...string) types.SerializedApplication {
	serialized := utils.TransferData[*Application, types.SerializedApplication](a)
	if a.OauthClient != nil {
		serialized.IsPublicClient = a.OauthClient.IsPublicClient
	}
	res := utils.Sanitizer(
		serialized,
		flags...,
	)

	policy := a.GetPolicy()
	if policy != nil {
		res.Privacy = policy.Privacy
		res.Terms = policy.Terms
	}

	return res
}

func (a *Application) IsOwner(userID string) bool {
	return a.OwnerID != nil && a.OwnerID.String() == userID
}

func (a *Application) AddPolicy(policy ApplicationPolicy) {
	for _, p := range a.Policies {
		p.IsActive = false
	}

	policy.IsActive = true
	a.Policies = append(a.Policies, policy)
}

func (a *Application) GetPolicy() *ApplicationPolicy {
	if len(a.Policies) == 0 {
		db, err := GetDatabase()
		var policy ApplicationPolicy
		if err != nil {
			return nil
		}

		err = db.Find(&policy, "application_id = ? AND is_active = true", a.ID).Error
		if err != nil {
			return nil
		}

		if policy.ID != uuid.Nil {
			return &policy
		}
		return nil
	}

	for _, p := range a.Policies {
		if p.IsActive {
			return &p
		}
	}

	return nil
}

// AllowedPermissions returns the permissions an admin allowed this application
// to request. They only take effect while AllowAnyPermission is unset.
func (a *Application) AllowedPermissions() ([]Permission, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}

	var permissions []Permission
	err = db.Where("id IN (?)", db.Model(&ApplicationPermission{}).Select("permission_id").Where("application_id = ?", a.ID)).
		Order("scope ASC").Find(&permissions).Error
	return permissions, err
}

// PermissionsOutsideLimit returns the given permissions this application may
// not request: those its allowed set does not cover.
// It is the one place the per-application limit is decided; only an application
// with AllowAnyPermission may request anything.
func (a *Application) PermissionsOutsideLimit(permissions []Permission) ([]Permission, error) {
	if a.AllowAnyPermission || len(permissions) == 0 {
		return nil, nil
	}

	allowed, err := a.AllowedPermissions()
	if err != nil {
		return nil, err
	}
	tree, err := LoadPermissionTree()
	if err != nil {
		return nil, err
	}
	return tree.Uncovered(allowed, permissions), nil
}

func (a *Application) GetConsentedLogs(user *User) ([]ApplicationConsentLog, error) {
	db, err := GetDatabaseWithPreload("Application", "User")
	if err != nil {
		return nil, err
	}

	var logs []ApplicationConsentLog
	db.Where("user_id = ? AND application_id = ? AND (revoked_at IS NULL OR revoked_at > ?)", user.ID, a.ID, time.Now()).Find(&logs)

	return logs, nil
}

func (a *Application) AuthorizedPermissions(user *User) ([]Permission, error) {
	logs, err := a.GetConsentedLogs(user)
	if err != nil {
		return nil, err
	}

	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}

	var ids []string
	err = db.Table("application_consent_logs_permissions").Distinct("permission_id").Find(&ids, "application_consent_log_id IN ?", utils.Map(logs, func(log ApplicationConsentLog) string {
		return log.ID.String()
	})).Error

	if err != nil {
		return nil, err
	}

	var permissions []Permission
	err = db.Find(&permissions, "id IN ?", ids).Error

	return permissions, nil
}

// ConsentPermissions returns what the user has to be asked for: the requested
// permissions an earlier grant to this application does not cover (all of them
// when force is set), folded for display.
func (a *Application) ConsentPermissions(user *User, perms []Permission, force bool) ([]Permission, error) {
	tree, err := LoadPermissionTree()
	if err != nil {
		return nil, err
	}

	if !force {
		granted, err := a.AuthorizedPermissions(user)
		if err != nil {
			return nil, err
		}
		perms = tree.Uncovered(granted, perms)
	}

	return tree.Fold(perms), nil
}

// Delete removes the application together with everything that hangs off it.
// The rows are deleted here because a soft delete triggers no database cascade.
func (a *Application) Delete() error {
	db, err := GetDatabase()
	if err != nil {
		return err
	}

	return db.Transaction(func(tx *gorm.DB) error {
		logs := tx.Model(&ApplicationConsentLog{}).Select("id").Where("application_id = ?", a.ID)
		if err := tx.Exec("DELETE FROM application_consent_logs_permissions WHERE application_consent_log_id IN (?)", logs).Error; err != nil {
			return err
		}

		for _, owned := range []struct {
			column string
			model  any
		}{
			{"application_id", &ApplicationConsentLog{}},
			{"application_id", &ApplicationPermission{}},
			{"application_id", &ApplicationPolicy{}},
			{"client_id", &OauthRedirectURI{}},
			{"client_id", &OauthPostLogoutRedirectURI{}},
			{"application_id", &ApplicationSession{}},
			{"client_id", &OauthCredential{}},
			{"client_id", &OauthClientAudience{}},
			{"application_id", &OauthClient{}},
		} {
			if err := tx.Where(owned.column+" = ?", a.ID).Delete(owned.model).Error; err != nil {
				return err
			}
		}

		return tx.Delete(a).Error
	})
}

// ApplicationPolicy contains an application's policies (terms, privacy).
type ApplicationPolicy struct {
	ID            uuid.UUID `gorm:"column:id;type:UUID;primary_key"`
	Privacy       string    `gorm:"column:privacy;not null"`
	Terms         string    `gorm:"column:terms;not null"`
	ApplicationID uuid.UUID `gorm:"column:application_id;type:UUID;not null;index"`
	IsActive      bool      `gorm:"column:is_active;not null;default:true"`
	UpdatedAt     time.Time `gorm:"column:updated_at;not null;default:CURRENT_TIMESTAMP"`
}

func (p *ApplicationPolicy) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

// ApplicationPermission embeds ApplicationPermissionFields from internal/models.
type ApplicationPermission struct {
	models.ApplicationPermissionFields `gorm:"embedded"`

	Application *Application `gorm:"foreignKey:ApplicationID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Permission  *Permission  `gorm:"foreignKey:PermissionID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}
