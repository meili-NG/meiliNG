package database

import (
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"gorm.io/gorm"
)

// UserData embeds UserDataFields from internal/models.
type UserData struct {
	models.UserDataFields `gorm:"embedded"`
}

func (u *UserData) AllowsUpdatingWithBypass(column string, bypass bool) bool {
	if bypass {
		return true
	}

	return u.AllowsUpdating(column)
}

// UserDataLockableColumns are the columns a lock can be set on.
var UserDataLockableColumns = []string{
	"name", "display_name", "first_name", "middle_name", "last_name", "birthday", "language", "timezone",
}

// AllowsUpdating reports whether the column is free of a lock. A lock is the
// value true under the column name in UserDataLocks. The name lock also holds
// display_name, because the OIDC name claim prefers it over name.
func (u *UserData) AllowsUpdating(column string) bool {
	locked, _ := u.UserDataLocks[column].(bool)
	nameLocked, _ := u.UserDataLocks["name"].(bool)
	return !locked && !(column == "display_name" && nameLocked)
}

func (u *UserData) BeforeCreate(tx *gorm.DB) error {
	if u.Metadata == nil {
		u.Metadata = map[string]any{}
	}

	if u.ExtraData == nil {
		u.ExtraData = map[string]any{}
	}

	if u.UserDataLocks == nil {
		u.UserDataLocks = map[string]any{}
	}

	emptyString := ""
	if u.MiddleName == nil {
		u.MiddleName = &emptyString
	}

	return nil
}

func (u *UserData) Serialize() types.SerializedUserData {
	middleName := ""
	if u.MiddleName != nil {
		middleName = *u.MiddleName
	}

	return types.SerializedUserData{
		Name:        u.Name,
		DisplayName: u.DisplayName,
		Birthday:    u.Birthday,
		Language:    u.Language,
		Timezone:    u.Timezone,

		FirstName:  u.FirstName,
		MiddleName: middleName,
		LastName:   u.LastName,
	}
}
