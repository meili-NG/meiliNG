package database

import (
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/pkg/avatar"
	"gorm.io/gorm"
)

var userPreloadTargets = []string{
	"Emails",
	"Phones",
	"UserNames",
	"Authenticators",
	"UserData",
}

func GetUserDB() (*gorm.DB, error) {
	return GetDatabaseWithPreload(userPreloadTargets...)
}

// User embeds UserFields from internal/models for DRY field definitions.
// Relations and GORM hooks are defined here.
type User struct {
	models.UserFields `gorm:"embedded"`

	// Relations
	Authenticators []UserAuthenticator     `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	UserNames      []UserName              `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Emails         []UserEmail             `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Phones         []UserPhone             `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	UserData       UserData                `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Applications   []Application           `gorm:"foreignKey:OwnerID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	ConsentLogs    []ApplicationConsentLog `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

// BeforeCreate will set a UUID rather than numeric ID.
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}

	if u.Data == nil {
		u.Data = map[string]any{}
	}

	return nil
}

func (u *User) GetOwnedApplications() []Application {
	return u.Applications
}

func (u *User) GetProfileURL() string {
	if u.UserData.AvatarUrl != nil {
		avatarUrl := *u.UserData.AvatarUrl
		if avatarUrl != "" {
			return *u.UserData.AvatarUrl
		}
	}

	if deps := GetDependencies(); deps != nil && deps.ResolveAvatar != nil {
		return deps.ResolveAvatar(avatar.User{ID: u.ID.String(), Email: u.GetPrimaryEmail()})
	}
	return ""
}

func (u *User) GetAuthorizedApplications() ([]Application, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}

	var consentLogs []ApplicationConsentLog
	err = db.Where("user_id = ?", u.ID).Distinct("application_id").Preload("Application").Find(&consentLogs).Error
	if err != nil {
		return nil, err
	}

	applications := utils.Map(consentLogs, func(log ApplicationConsentLog) Application {
		return log.Application
	})

	return applications, nil
}

func (u *User) NewSignInLog(sessionID uuid.UUID, ip string) *SignInLog {
	return &SignInLog{
		SignInLogFields: models.SignInLogFields{
			UserID:     u.ID,
			SessionID:  sessionID,
			SignedInAt: time.Now(),
			IP:         ip,
		},
		User: u,
	}
}

func (u *User) IsValid() bool {
	return u.ID != uuid.Nil
}

func (u *User) Serialize() types.UserSerialized {
	res := types.UserSerialized{
		ID:               u.ID.String(),
		Usernames:        u.GetUsernames(),
		Emails:           u.GetEmailsStrings(),
		Phones:           u.GetPhonesStrings(),
		TwoFactorEnabled: u.TwoFactorEnabled,
		MaxApplications:  u.MaxApplications,
		DeletedAt:        u.DeletedAt,
	}

	if u.UserData.UserID != uuid.Nil {
		serialized := u.UserData.Serialize()
		res.UserData = &serialized
	}

	return res
}

func (u *User) GetEmailsStrings() []string {
	return utils.Map(u.GetEmails(), func(email types.AddEmailRequest) string {
		return email.Email
	})
}

func (u *User) GetEmails() []types.AddEmailRequest {
	return utils.Map(u.Emails, func(email UserEmail) types.AddEmailRequest {
		req := types.AddEmailRequest{
			Email: email.Email,
		}

		req.Verified = email.Verified
		return req
	})
}

func (u *User) IsEmailVerified(email string) bool {
	for _, e := range u.Emails {
		if e.Email == email {
			return e.Verified
		}
	}

	return false
}

func (u *User) GetPrimaryEmail() string {
	for _, e := range u.Emails {
		if e.IsPrimary {
			return e.Email
		}
	}

	return ""
}

func (u *User) GetPrimaryPhone() string {
	for _, p := range u.Phones {
		if p.IsPrimary {
			return p.Phone
		}
	}

	return ""
}

func (u *User) IsPhoneVerified(phone string) bool {
	for _, p := range u.Phones {
		if p.Phone == phone {
			return p.Verified
		}
	}

	return false
}

func (u *User) GetPhones() []types.AddPhoneRequest {
	return utils.Map(u.Phones, func(phone UserPhone) types.AddPhoneRequest {
		req := types.AddPhoneRequest{
			Phone: phone.Phone,
		}

		req.Verified = phone.Verified
		return req
	})
}

func (u *User) GetPhonesStrings() []string {
	return utils.Map(u.GetPhones(), func(phone types.AddPhoneRequest) string {
		return phone.Phone
	})
}

func (u *User) GetVerifiedEmails() []string {
	var emails []string = make([]string, 0)
	for _, email := range u.Emails {
		if email.Verified {
			emails = append(emails, email.Email)
		}
	}

	return emails
}

func (u *User) GetVerifiedPhones() []string {
	var phones []string = make([]string, 0)
	for _, phone := range u.Phones {
		if phone.Verified {
			phones = append(phones, phone.Phone)
		}
	}

	return phones
}

// UserName embeds UserNameFields from internal/models.
type UserName struct {
	models.UserNameFields `gorm:"embedded"`
	User                  User `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

// UserEmail embeds UserEmailFields from internal/models.
type UserEmail struct {
	models.UserEmailFields `gorm:"embedded"`
	User                   User `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

// BeforeCreate will set a UUID rather than numeric ID.
func (u *UserEmail) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// UserPhone embeds UserPhoneFields from internal/models.
type UserPhone struct {
	models.UserPhoneFields `gorm:"embedded"`
	User                   User `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

// BeforeCreate will set a UUID rather than numeric ID.
func (u *UserPhone) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}

	return nil
}
