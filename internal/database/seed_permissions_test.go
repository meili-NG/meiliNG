package database

import (
	"testing"

	"github.com/meili-NG/meiliNG/v2/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupPermissionSeedDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&Permission{}); err != nil {
		t.Fatalf("AutoMigrate Permission: %v", err)
	}

	return db
}

func TestSeedOIDCPermissionsCreatesLocalizedMessages(t *testing.T) {
	db := setupPermissionSeedDB(t)

	if err := SeedOIDCPermissions(db); err != nil {
		t.Fatalf("SeedOIDCPermissions: %v", err)
	}

	var permission Permission
	if err := db.First(&permission, "scope = ?", "profile").Error; err != nil {
		t.Fatalf("find profile permission: %v", err)
	}

	messages := permission.GetLocalizedMessages()
	if messages["en"] != "Access to your basic profile information such as name, profile picture and other publicly displayed basic profile information." {
		t.Fatalf("profile en message = %#v", messages["en"])
	}
	if messages["ko"] != "이름, 프로필 사진 및 기타 공개적으로 표시되는 기본 프로필 정보에 접근합니다." {
		t.Fatalf("profile ko message = %#v", messages["ko"])
	}
}

func TestSeedOIDCPermissionsKeepsExistingRows(t *testing.T) {
	db := setupPermissionSeedDB(t)

	if err := db.Create(&Permission{PermissionFields: models.PermissionFields{
		Scope:   "phone",
		Message: "Custom phone message",
	}}).Error; err != nil {
		t.Fatalf("create phone permission: %v", err)
	}

	if err := SeedOIDCPermissions(db); err != nil {
		t.Fatalf("SeedOIDCPermissions: %v", err)
	}

	var phone Permission
	if err := db.First(&phone, "scope = ?", "phone").Error; err != nil {
		t.Fatalf("find phone permission: %v", err)
	}
	if phone.Message != "Custom phone message" || phone.LocalizedMessagesJSON != "" || phone.IsDefault {
		t.Fatalf("seeding changed an existing permission: %#v", phone.PermissionFields)
	}
}

func seededDefaultFlags(t *testing.T, db *gorm.DB) map[string]bool {
	t.Helper()

	var permissions []Permission
	if err := db.Find(&permissions).Error; err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	flags := make(map[string]bool, len(permissions))
	for _, permission := range permissions {
		flags[permission.Scope] = permission.IsDefault
	}
	return flags
}

// TestSeedOIDCPermissionsAreDefaultOnlyInEmptyTable starts from an empty
// permissions table, which is also what a first start interrupted before
// seeding leaves behind.
func TestSeedOIDCPermissionsAreDefaultOnlyInEmptyTable(t *testing.T) {
	db := setupPermissionSeedDB(t)

	if err := SeedOIDCPermissions(db); err != nil {
		t.Fatalf("SeedOIDCPermissions: %v", err)
	}
	flags := seededDefaultFlags(t, db)
	for _, def := range defaultOIDCPermissions {
		if !flags[def.Scope] {
			t.Fatalf("seeded permission %q is not default in an empty table: %#v", def.Scope, flags)
		}
	}

	if err := db.Where("scope = ?", "email").Delete(&Permission{}).Error; err != nil {
		t.Fatalf("delete email: %v", err)
	}
	if err := SeedOIDCPermissions(db); err != nil {
		t.Fatalf("SeedOIDCPermissions on restart: %v", err)
	}

	flags = seededDefaultFlags(t, db)
	isDefault, exists := flags["email"]
	if !exists {
		t.Fatal("a restart did not seed the deleted email permission again")
	}
	if isDefault {
		t.Fatal("a restart brought the deleted email permission back as default")
	}
	if !flags["openid"] {
		t.Fatal("a restart cleared the default flag of openid")
	}
}
