package database

import (
	jsoniter "github.com/json-iterator/go"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// defaultOIDCPermission describes a standard OpenID Connect scope that must
// exist as a Permission row for the OAuth2/OIDC flows to accept it. Without
// these, resolveOAuth2PermissionsFromScope rejects every request that asks for
// "openid", "profile", etc., so OIDC does not function on a fresh instance.
type defaultOIDCPermission struct {
	Scope   string
	Message string
	// LocalizedMessages maps a locale code (e.g. "en", "ko") to the consent
	// prompt shown for this scope in that language. The "en" entry mirrors
	// Message and acts as the fallback when a locale is missing.
	LocalizedMessages map[string]string
}

// defaultOIDCPermissions are the baseline scopes seeded on startup. They map to
// the claims the ID token and userinfo endpoint can emit. All are public so
// they appear in the discovery document's scopes_supported, and a first install
// makes them default so every application can request them.
var defaultOIDCPermissions = []defaultOIDCPermission{
	{
		Scope:   "openid",
		Message: "Access to authentication for identity verification.",
		LocalizedMessages: map[string]string{
			"en": "Access to authentication for identity verification.",
			"ko": "신원 확인을 위한 인증에 접근합니다.",
		},
	},
	{
		Scope:   "profile",
		Message: "Access to your basic profile information such as name, profile picture and other publicly displayed basic profile information.",
		LocalizedMessages: map[string]string{
			"en": "Access to your basic profile information such as name, profile picture and other publicly displayed basic profile information.",
			"ko": "이름, 프로필 사진 및 기타 공개적으로 표시되는 기본 프로필 정보에 접근합니다.",
		},
	},
	{
		Scope:   "email",
		Message: "Access to your email address.",
		LocalizedMessages: map[string]string{
			"en": "Access to your email address.",
			"ko": "이메일 주소에 접근합니다.",
		},
	},
	{
		Scope:   "phone",
		Message: "Access to your phone number.",
		LocalizedMessages: map[string]string{
			"en": "Access to your phone number.",
			"ko": "전화번호에 접근합니다.",
		},
	},
	{
		Scope:   "address",
		Message: "Access to your address.",
		LocalizedMessages: map[string]string{
			"en": "Access to your address.",
			"ko": "주소에 접근합니다.",
		},
	},
	{
		Scope:   "offline_access",
		Message: "Maintain access to your account when you're offline.",
		LocalizedMessages: map[string]string{
			"en": "Maintain access to your account when you're offline.",
			"ko": "오프라인 상태일 때에도 계정에 대한 접근을 유지합니다.",
		},
	},
}

// SeedOIDCPermissions ensures the standard OIDC scopes exist as public
// permissions. It is idempotent: existing scopes are matched on the unique
// scope column and left as they are. Scopes created in an empty permissions
// table, a first install, are default permissions; a scope created on any
// later start is not, so one an administrator deleted comes back without the
// flag.
func SeedOIDCPermissions(instance *gorm.DB) error {
	if instance == nil {
		return nil
	}

	// One transaction, so an interrupted first start cannot seed only some scopes as default.
	return instance.Transaction(func(tx *gorm.DB) error {
		var existing int64
		if err := tx.Model(&Permission{}).Count(&existing).Error; err != nil {
			return err
		}

		for _, def := range defaultOIDCPermissions {
			localizedMessages, err := jsoniter.ConfigFastest.MarshalToString(def.LocalizedMessages)
			if err != nil {
				return err
			}

			permission := Permission{
				PermissionFields: models.PermissionFields{
					Scope:                 def.Scope,
					Message:               def.Message,
					LocalizedMessagesJSON: localizedMessages,
					IsPublic:              true,
					IsDefault:             existing == 0,
				},
			}

			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "scope"}},
				DoNothing: true,
			}).Create(&permission).Error; err != nil {
				return err
			}
		}

		return nil
	})
}
