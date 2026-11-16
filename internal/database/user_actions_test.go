package database

import (
	"fmt"
	"testing"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupUserActionsDB(t *testing.T) *gorm.DB {
	t.Helper()

	ResetInstance()
	SetDatabaseConfig(&DatabaseConfig{
		Type: "sqlite",
		DSN:  fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()),
	})
	SetDependencies(&Dependencies{
		GeneralizePhone: func(phone string) (string, error) {
			return phone, nil
		},
		GetDialector: func(cfg *DatabaseConfig) gorm.Dialector {
			return sqlite.Open(cfg.DSN)
		},
	})

	if err := InitializeMainDB(); err != nil {
		t.Fatalf("InitializeMainDB: %v", err)
	}

	db, err := GetDatabase()
	if err != nil {
		t.Fatalf("GetDatabase: %v", err)
	}

	return db
}

func TestUserEmailMutationsKeepPrimaryAndUpdateFlags(t *testing.T) {
	db := setupUserActionsDB(t)

	user, err := NewUser()
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	if err := user.AddEmail("primary@example.com", false); err != nil {
		t.Fatalf("AddEmail primary: %v", err)
	}
	if err := user.AddEmail("secondary@example.com", false); err != nil {
		t.Fatalf("AddEmail secondary: %v", err)
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Create user: %v", err)
	}

	user.UpdateEmail("primary@example.com", types.UpdateEmailRequest{Verified: true})
	if !user.Emails[0].Verified {
		t.Fatalf("primary email should be verified after update: %#v", user.Emails)
	}

	user.RemoveEmail("primary@example.com")
	if len(user.Emails) != 1 {
		t.Fatalf("email count = %d, want 1", len(user.Emails))
	}
	if user.Emails[0].Email != "secondary@example.com" || !user.Emails[0].IsPrimary {
		t.Fatalf("remaining emails = %#v, want secondary promoted to primary", user.Emails)
	}

	var count int64
	if err := db.Model(&UserEmail{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("Count emails: %v", err)
	}
	if count != 1 {
		t.Fatalf("persisted email count = %d, want 1", count)
	}
}

func TestUserPhoneMutationsUpdateFlagsAndDelete(t *testing.T) {
	db := setupUserActionsDB(t)

	user, err := NewUser()
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	if err := user.AddPhone("+12025550123", false); err != nil {
		t.Fatalf("AddPhone: %v", err)
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Create user: %v", err)
	}

	if err := user.UpdatePhone("+12025550123", types.UpdatePhoneRequest{Verified: true}); err != nil {
		t.Fatalf("UpdatePhone: %v", err)
	}
	if !user.Phones[0].Verified {
		t.Fatalf("phone should be verified after update: %#v", user.Phones)
	}

	if err := user.RemovePhone("+12025550123"); err != nil {
		t.Fatalf("RemovePhone: %v", err)
	}
	if len(user.Phones) != 0 {
		t.Fatalf("phone count = %d, want 0", len(user.Phones))
	}

	var count int64
	if err := db.Model(&UserPhone{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("Count phones: %v", err)
	}
	if count != 0 {
		t.Fatalf("persisted phone count = %d, want 0", count)
	}
}
