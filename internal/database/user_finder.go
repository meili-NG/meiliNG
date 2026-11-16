package database

import (
	"net/mail"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
)

type UserFinder struct{}

func (f *UserFinder) FindByID(id string) (*User, error) {
	db, err := GetUserDB()
	if err != nil {
		return nil, err
	}

	var user User
	db.Find(&user, "id = ?", id)

	zeroUuid := uuid.UUID{}
	if user.ID == zeroUuid {
		return nil, nil
	}

	return &user, nil
}

// SignInLookup says which identifiers find a user at sign-in.
type SignInLookup struct {
	Username        bool
	Email           bool
	UnverifiedEmail bool
}

// FindBySignInIdentifier finds the user identifier names: an email address,
// verified first, then a username, as lookup allows. It returns nil when none
// matches.
func (f *UserFinder) FindBySignInIdentifier(identifier string, lookup SignInLookup) (*User, error) {
	if _, err := mail.ParseAddress(identifier); err == nil && lookup.Email {
		user, err := f.FindByEmail(identifier, true)
		if err != nil || user != nil {
			return user, err
		}
		if lookup.UnverifiedEmail {
			user, err := f.FindByEmail(identifier, false)
			if err != nil || user != nil {
				return user, err
			}
		}
	}

	if !lookup.Username {
		return nil, nil
	}
	return f.FindByUserName(identifier)
}

func (f *UserFinder) FindByUserName(username string) (*User, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}

	var userName UserName
	db.Find(&userName, "LOWER(username) = LOWER(?)", username)

	var user User
	userDB, err := GetUserDB()
	if err != nil {
		return nil, err
	}
	userDB.Find(&user, "id = ? AND deleted_at IS NULL", userName.UserID)

	zeroUuid := uuid.UUID{}
	if user.ID == zeroUuid {
		return nil, nil
	}

	return &user, nil
}

func (f *UserFinder) FindByPhone(phone string, onlyVerified bool) (*User, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}

	var userPhone UserPhone
	cond := "phone = ?"
	if onlyVerified {
		cond += " AND verified = true"
	}
	db.Find(&userPhone, cond, phone)

	var user User
	userDB, err := GetUserDB()
	if err != nil {
		return nil, err
	}

	userDB.Find(&user, "id = ? AND deleted_at IS NULL", userPhone.UserID)

	zeroUuid := uuid.UUID{}
	if user.ID == zeroUuid {
		return nil, nil
	}

	return &user, nil
}

func (f *UserFinder) FindByEmail(email string, onlyVerified bool) (*User, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}

	var userEmails []UserEmail
	cond := "LOWER(email) = LOWER(?)"
	if onlyVerified {
		cond += " AND verified = true"
	}
	db.Find(&userEmails, cond, email)

	var user User
	userDB, err := GetUserDB()
	if err != nil {
		return nil, err
	}

	userDB.Find(&user, "id IN ? AND deleted_at IS NULL", utils.Map(userEmails, func(email UserEmail) string {
		return email.UserID.String()
	}))

	zeroUuid := uuid.UUID{}
	if user.ID == zeroUuid {
		return nil, nil
	}

	return &user, nil
}
