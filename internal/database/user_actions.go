package database

import (
	"errors"
	authpassword "github.com/meili-NG/meiliNG/v2/pkg/auth/password"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/pquerna/otp"
	"golang.org/x/crypto/bcrypt"
)

// GeneralizePhone normalizes a phone number using the configured dependency
func GeneralizePhone(phone string) (string, error) {
	deps := GetDependencies()
	if deps == nil || deps.GeneralizePhone == nil {
		return "", errors.New("GeneralizePhone dependency not configured")
	}
	return deps.GeneralizePhone(phone)
}

func NewUser() (*User, error) {
	id := uuid.New()

	return &User{
		UserFields: models.UserFields{
			ID:               id,
			TwoFactorEnabled: false,
			DeletedAt:        nil,
		},
		UserNames:      make([]UserName, 0),
		Emails:         make([]UserEmail, 0),
		Phones:         make([]UserPhone, 0),
		Authenticators: make([]UserAuthenticator, 0),
	}, nil
}

func NewPasswordAuthenticator(password string) (*PasswordValidator, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return &PasswordValidator{
		PasswordType: authpassword.SchemeBcrypt,
		Data:         string(hash),
	}, nil
}

func (u *User) AddPassword(password string) error {
	// prevent duplicate password
	existing := u.FindPasswordAuthenticator(password)
	if existing != nil {
		return nil
	}

	passwordAuthn, err := NewPasswordAuthenticator(password)
	if err != nil {
		return err
	}

	authn, err := passwordAuthn.SerializeAuthenticator()
	if err != nil {
		return err
	}

	u.AddAuthenticator(authn)

	userDB, err := GetUserDB()
	if err != nil {
		return err
	}

	userDB.Updates(u)
	return nil
}

func (u *User) AddTOTP(key *otp.Key, note string) error {
	otpAuthn := &TOTPValidator{
		Secret: key.Secret(),
	}

	authn, err := otpAuthn.SerializeAuthenticator()
	if err != nil {
		return err
	}

	if note != "" {
		authn.Note = note
	}

	u.AddAuthenticator(authn)
	return nil
}

func (u *User) AddBackupCode(code string) (*UserAuthenticator, error) {
	backupCodeAuthn, err := NewBackupCodeValidator(code)
	if err != nil {
		return nil, err
	}

	authn, err := backupCodeAuthn.SerializeAuthenticator()
	if err != nil {
		return nil, err
	}

	authn.UserID = u.ID
	u.AddAuthenticator(authn)
	return authn, nil
}

func (u *User) HasTwoFactorAuthn() bool {
	for _, auth := range u.Authenticators {
		if auth.Allow2FA && auth.Type != (&BackupCodeValidator{}).Type() {
			return true
		}
	}

	return false
}

func (u *User) ClearBackupCodes() error {
	db, err := GetDatabase()
	if err != nil {
		return err
	}

	if err := db.Where("user_id = ? AND type = ?", u.ID, (&BackupCodeValidator{}).Type()).Delete(&UserAuthenticator{}).Error; err != nil {
		return err
	}

	u.Authenticators = utils.Filter(u.Authenticators, func(auth UserAuthenticator) bool {
		return auth.Type != (&BackupCodeValidator{}).Type()
	})
	return nil
}

func (u *User) DisableTwoFactor() error {
	db, err := GetDatabase()
	if err != nil {
		return err
	}

	u.TwoFactorEnabled = false
	err = db.Model(u).Updates(utils.SerializeGORMColumnsToMap(u, "TwoFactorEnabled")).Error
	if err != nil {
		return err
	}

	return u.ClearBackupCodes()
}

func (u *User) RemovePassword(password string) error {
	// get matching password authenticator
	auth := u.FindPasswordAuthenticator(password)
	if auth == nil {
		return meilingErrors.New(meilingErrors.ErrUnauthorized, "invalid password")
	}

	for i, a := range u.Authenticators {
		if a.ID == auth.ID {
			db, err := GetDatabase()
			if err != nil {
				return err
			}

			db.Delete(&u.Authenticators[i])
			u.Authenticators = append(u.Authenticators[:i], u.Authenticators[i+1:]...)
		}
	}

	return nil
}

func (u *User) SetPassword(newPassword string) error {
	validatorType := (&PasswordValidator{}).Type()

	passwordAuthns := u.GetAuthenticators(validatorType)
	if len(passwordAuthns) > 0 {
		db, err := GetDatabase()
		if err != nil {
			return err
		}

		// remove all
		for _, auth := range passwordAuthns {
			err = db.Delete(&auth).Error
			if err != nil {
				return err
			}
		}
	}

	// remove all password authenticators
	u.Authenticators = utils.Filter(u.Authenticators, func(auth UserAuthenticator) bool {
		return auth.Type != validatorType
	})

	return u.AddPassword(newPassword)
}

func (u *User) ChangePassword(prevPassword string, newPassword string) error {
	if err := u.RemovePassword(prevPassword); err != nil {
		return err
	} else if err = u.AddPassword(newPassword); err != nil {
		return err
	}

	return nil
}

func (u *User) GetUsernames() []string {
	usernames := make([]string, 0)
	for _, un := range u.UserNames {
		usernames = append(usernames, un.Username)
	}

	return usernames
}

func (u *User) RemoveAllUserNames() error {
	if u.UserNames == nil {
		return errors.New("no usernames to remove")
	}
	db, err := GetDatabase()
	if err != nil {
		return err
	}

	for _, un := range u.UserNames {
		db.Delete(&un)
	}

	u.UserNames = []UserName{}
	return nil
}

func (u *User) RemoveUserName(username string) {
	if u.UserNames == nil {
		return
	}

	db, err := GetDatabase()
	if err == nil {
		for i, un := range u.UserNames {
			if un.Username == username {
				db.Delete(&u.UserNames[i])
				u.UserNames = append(u.UserNames[:i], u.UserNames[i+1:]...)
				return
			}
		}
	}
}

func (u *User) GetPrimaryUserName() string {
	for _, un := range u.UserNames {
		if un.Username != "" {
			return un.Username
		}
	}

	for _, e := range u.GetEmailsStrings() {
		if e != "" {
			return e
		}
	}

	return ""
}

func (u *User) ChangeUserName(username string) error {
	if v := u.RemoveAllUserNames(); v == nil {
		u.UserNames = append(u.UserNames, UserName{
			UserNameFields: models.UserNameFields{
				Username: username,
			},
		})
		return nil
	} else {
		return v
	}
}

func (u *User) AddEmail(email string, verified bool) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return err
	}

	if u.Emails == nil {
		u.Emails = []UserEmail{}
	}

	isPrimary := len(u.Emails) == 0
	if !isPrimary {
		allNotPrimary := true
		for _, e := range u.Emails {
			if e.IsPrimary {
				allNotPrimary = false
			}

			if e.Email == email {
				if !e.Verified && verified {
					e.Verified = true
				}
				return nil
			}
		}

		if allNotPrimary {
			isPrimary = true
		}
	}

	u.Emails = append(u.Emails, UserEmail{
		UserEmailFields: models.UserEmailFields{
			Email:     email,
			Verified:  verified,
			IsPrimary: isPrimary,
		},
	})

	return nil
}

func (u *User) RemoveEmail(email string) {
	if u.Emails == nil {
		return
	}

	db, err := GetDatabase()
	if err == nil {
		for i, e := range u.Emails {
			if e.Email == email {
				if e.IsPrimary {
					if len(u.Emails) > 1 {
						u.Emails[i+1].IsPrimary = true
					}
				}

				db.Delete(&u.Emails[i])
				u.Emails = append(u.Emails[:i], u.Emails[i+1:]...)
				return
			}
		}
	}
}

func (u *User) UpdateEmail(email string, payload types.UpdateEmailRequest) {
	if u.Emails == nil {
		return
	}

	for i, e := range u.Emails {
		if e.Email == email {
			utils.TransferUpdates[types.UpdateEmailRequest, UserEmail](payload, &u.Emails[i])
		}
	}
}

func (u *User) AddPhone(phone string, verified bool) error {
	if u.Phones == nil {
		u.Phones = []UserPhone{}
	}

	processed, err := GeneralizePhone(phone)
	if err != nil {
		return err
	}

	// check if same phone number already exists
	for _, p := range u.Phones {
		if p.Phone == processed {
			if !p.Verified && verified {
				p.Verified = true
			}
			return nil
		}
	}

	u.Phones = append(u.Phones, UserPhone{
		UserPhoneFields: models.UserPhoneFields{
			Phone:    processed,
			Verified: verified,
		},
	})
	return nil
}

func (u *User) UpdatePhone(phone string, payload types.UpdatePhoneRequest) error {
	if u.Phones == nil {
		return nil
	}

	generalized, err := GeneralizePhone(phone)
	if err != nil {
		return err
	}

	for i, p := range u.Phones {
		if p.Phone == generalized {
			utils.TransferUpdates[types.UpdatePhoneRequest, UserPhone](payload, &u.Phones[i])
		}
	}

	return nil
}

func (u *User) RemovePhone(phone string) error {
	if u.Phones == nil {
		return nil
	}

	generalized, err := GeneralizePhone(phone)
	if err != nil {
		return err
	}

	db, err := GetDatabase()
	if err == nil {
		for i, p := range u.Phones {
			if p.Phone == generalized {
				db.Delete(&u.Phones[i])
				u.Phones = append(u.Phones[:i], u.Phones[i+1:]...)
				return nil
			}
		}
	}
	return nil
}

func (u *User) addUserNameIgnoreDuplicate(username string) {
	if u.UserNames == nil {
		u.UserNames = []UserName{}
	}

	username = strings.ToLower(username)
	for _, un := range u.UserNames {
		if un.Username == username {
			return
		}
	}

	u.UserNames = append(u.UserNames, UserName{
		UserNameFields: models.UserNameFields{
			Username: username,
		},
	})
}

func (u *User) AddUserName(username string) error {
	db, err := GetDatabase()
	if err != nil {
		return err
	}

	var existing UserName
	db.Where("username = ?", username).First(&existing)
	if existing.Username != "" {
		if existing.UserID == u.ID {
			return nil
		}
		return meilingErrors.New(meilingErrors.ErrUsernameAlreadyTaken, "username already taken")
	}

	u.addUserNameIgnoreDuplicate(username)
	return nil

}

func (u *User) AddAuthenticator(authenticator *UserAuthenticator) {
	if u.Authenticators == nil {
		u.Authenticators = []UserAuthenticator{}
	}

	u.Authenticators = append(u.Authenticators, *authenticator)
}

func (u *User) GetAuthenticators(validatorType string) []UserAuthenticator {
	authenticators := []UserAuthenticator{}
	for _, auth := range u.Authenticators {
		validator, err := auth.GetValidator()
		if err != nil {
			continue
		}

		if validator.Type() == validatorType {
			authenticators = append(authenticators, auth)
		}
	}

	return authenticators
}

func (u *User) FindPasswordAuthenticator(password string) *UserAuthenticator {
	validatorType := (&PasswordValidator{}).Type()
	for _, auth := range u.GetAuthenticators(validatorType) {
		validator, err := auth.GetValidator()
		if err != nil {
			continue
		}

		pwValidator, ok := validator.(*PasswordValidator)
		if ok {
			valid, err := pwValidator.ValidatePassword(password)
			if err != nil || !valid {
				continue
			}
			return &auth
		}
	}

	return nil
}

func (u *User) CheckPassword(password string) bool {
	auth := u.FindPasswordAuthenticator(password)
	if auth != nil {
		return true
	}

	return false
}
