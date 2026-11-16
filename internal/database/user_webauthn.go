package database

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
)

type UserWebAuthnCredential struct {
	webauthn.User
	user                  *User
	allowedAuthenticators []UserAuthenticator
}

func (c *UserWebAuthnCredential) WebAuthnID() []byte {
	id, err := c.user.ID.MarshalBinary()
	if err != nil {
		return []byte{}
	}

	return id
}

func (c *UserWebAuthnCredential) WebAuthnName() string {
	// try getting user's name
	if c.user.UserData.Name == "" {
		return c.user.UserData.Name
	}

	// name does not exist. try using user's username
	usernames := c.user.GetUsernames()
	if len(usernames) > 0 {
		return usernames[0]
	}

	// no username, fallback to email
	emails := c.user.GetEmailsStrings()
	if len(emails) > 0 {
		return emails[0]
	}

	// no email, fallback to phone
	phones := c.user.GetPhonesStrings()
	if len(phones) > 0 {
		return phones[0]
	}

	// no phone, fallback to user id
	return c.user.ID.String()
}

func (c *UserWebAuthnCredential) WebAuthnDisplayName() string {
	if c.user.UserData.DisplayName == "" {
		return c.user.UserData.DisplayName
	}
	return c.WebAuthnName()
}

func (c *UserWebAuthnCredential) WebAuthnCredentials() []webauthn.Credential {
	if c.allowedAuthenticators == nil {
		// fallback to getting user's authenticators

		db, err := GetDatabase()
		if db == nil || err != nil {
			return []webauthn.Credential{}
		}

		var authenticators []UserAuthenticator
		db.Find(&authenticators, "user_id = ? AND type = ?", c.user.ID, (&WebAuthnValidator{}).Type())

		credentials := utils.Filter(
			utils.Map(authenticators, func(authenticator UserAuthenticator) webauthn.Credential {
				validator, err := authenticator.GetValidator()
				if v, ok := validator.(*WebAuthnValidator); ok && err == nil {
					return v.Credential
				} else {
					return webauthn.Credential{
						ID: nil,
					}
				}
			}),
			func(credential webauthn.Credential) bool {
				return credential.ID != nil
			})

		return credentials
	} else {
		credentials := make([]webauthn.Credential, 0)
		for _, authenticator := range c.allowedAuthenticators {
			validator, err := authenticator.GetValidator()
			if v, ok := validator.(*WebAuthnValidator); ok && err == nil {
				credentials = append(credentials, v.Credential)
			}
		}

		return credentials
	}
}

func (c *UserWebAuthnCredential) GetWebAuthnUser() webauthn.User {
	return c
}

func (c *UserWebAuthnCredential) SetAllowedAuthenticators(authenticators []UserAuthenticator) {
	c.allowedAuthenticators = authenticators
}

func (u *User) GetWebAuthn() webauthn.User {
	credential := UserWebAuthnCredential{
		user: u,
	}
	return credential.GetWebAuthnUser()
}
