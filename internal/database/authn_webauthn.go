package database

import (
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
)

// getWebAuthn returns the WebAuthn instance from dependencies
func getWebAuthn() (*webauthn.WebAuthn, error) {
	deps := GetDependencies()
	if deps == nil || deps.WebAuthn == nil {
		return nil, errors.New("WebAuthn dependency not configured")
	}
	return deps.WebAuthn()
}

type WebAuthnValidator struct {
	UserAuthValidator
	id         uuid.UUID
	Credential webauthn.Credential `json:"credential"`
	user       *User
}

func NewWebAuthnValidator(u *User) (*WebAuthnValidator, error) {
	return &WebAuthnValidator{
		user: u,
	}, nil
}

func (validator *WebAuthnValidator) IsValid() bool {
	return validator.Credential.ID != nil
}

func (validator *WebAuthnValidator) Register() (options *protocol.CredentialCreation, sessionData *webauthn.SessionData, err error) {
	webAuthn, err := getWebAuthn()
	if err != nil {
		return nil, nil, err
	}

	if validator.user == nil {
		return nil, nil, errors.New("user is nil")
	}

	return webAuthn.BeginRegistration(validator.user.GetWebAuthn())
}

func (validator *WebAuthnValidator) ValidateRegister(response *protocol.ParsedCredentialCreationData, sessionData webauthn.SessionData) (credential *webauthn.Credential, err error) {
	webAuthn, err := getWebAuthn()
	if err != nil {
		return nil, err
	}

	credential, err = webAuthn.CreateCredential(validator.user.GetWebAuthn(), sessionData, response)
	if err != nil {
		return nil, err
	}

	validator.Credential = *credential
	return credential, nil
}

func (validator *WebAuthnValidator) AuthenticateWebAuthn() (options *protocol.CredentialAssertion, sessionData *webauthn.SessionData, err error) {
	webAuthn, err := getWebAuthn()
	if err != nil {
		return nil, nil, err
	}

	// Without a known user, start a discoverable-credential login.
	if validator.user == nil {
		return webAuthn.BeginDiscoverableLogin()
	} else {
		return webAuthn.BeginLogin(validator.user.GetWebAuthn())
	}
}

func (validator *WebAuthnValidator) ValidateWebAuthn(response *protocol.ParsedCredentialAssertionData, sessionData webauthn.SessionData) error {
	webAuthn, err := getWebAuthn()
	if err != nil {
		return err
	}

	var credential *webauthn.Credential

	if validator.user == nil {
		_, credential, err = webAuthn.ValidatePasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			var target UserAuthenticator

			db, err := GetDatabase()
			db.First(&target, "identifier = ? AND type = ?", utils.Base64Encode(rawID), validator.Type())
			if err != nil {
				return nil, err
			}

			thisValidator, err := target.GetWebAuthnValidator()
			if err != nil {
				return nil, err
			}

			validator.Credential = thisValidator.Credential
			validator.user = thisValidator.user

			return validator.user.GetWebAuthn(), nil
		}, sessionData, response)
	} else {
		credential, err = webAuthn.ValidateLogin(validator.user.GetWebAuthn(), sessionData, response)
	}

	if err != nil {
		return err
	}

	validator.Credential = *credential
	return nil
}

func (validator *WebAuthnValidator) Type() string {
	return "webauthn"
}

func (validator *WebAuthnValidator) RequireChallenge() bool {
	return true
}

func (validator *WebAuthnValidator) IssueChallenge() (optionsJSON string, sessionJSON string, err error) {
	options, sessionData, err := validator.AuthenticateWebAuthn()
	if err != nil {
		return "", "", err
	}

	res, err := json.MarshalToString(options)
	if err != nil {
		return "", "", err
	}

	sess, err := json.MarshalToString(sessionData)
	if err != nil {
		return "", "", err
	}

	return res, sess, nil
}

func (validator *WebAuthnValidator) SetUserOnSession(sessionJSON string) (string, error) {
	var parsedExpected webauthn.SessionData
	err := json.UnmarshalFromString(sessionJSON, &parsedExpected)
	if err != nil {
		return "", errors.New("invalid session data")
	}

	parsedExpected.UserID = validator.user.GetWebAuthn().WebAuthnID()
	return json.MarshalToString(parsedExpected)
}

func (validator *WebAuthnValidator) ValidateChallenge(response string, expected string) (bool, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(response))
	if err != nil {
		return false, err
	}

	var parsedExpected webauthn.SessionData
	err = json.UnmarshalFromString(expected, &parsedExpected)
	if err != nil {
		return false, err
	}

	err = validator.ValidateWebAuthn(parsed, parsedExpected)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (validator *WebAuthnValidator) SerializeData() map[string]any {
	return map[string]any{
		"credentials": utils.SerializeToMap(validator.Credential),
	}
}

func (validator *WebAuthnValidator) DeserializeData(data map[string]any) error {
	if v, ok := data["credentials"].(map[string]any); !ok {
		return errors.New("invalid webauthn credential")
	} else {
		res, err := json.Marshal(v)
		if err != nil {
			return err
		}

		err = json.Unmarshal(res, &validator.Credential)
		if err != nil {
			return err
		}
	}

	return nil
}

func (validator *WebAuthnValidator) SerializeAuthenticator() (*UserAuthenticator, error) {
	identifier := validator.GetIdentifier()
	return &UserAuthenticator{
		UserAuthenticatorFields: models.UserAuthenticatorFields{
			ID:                validator.GetID(),
			Type:              validator.Type(),
			Data:              validator.SerializeData(),
			Identifier:        identifier,
			AllowSignIn:       false,
			Allow2FA:          true,
			AllowPasswordless: true,
		},
	}, nil
}

func (validator *WebAuthnValidator) GetIdentifier() *string {
	base64 := utils.Base64Encode(validator.Credential.ID)
	return &base64
}

func (validator *WebAuthnValidator) GetExpiresAt() time.Time {
	return time.Now().Add(time.Minute * 10)
}

func (validator *WebAuthnValidator) GetID() uuid.UUID {
	if validator.id == uuid.Nil {
		validator.id = uuid.New()
	}

	return validator.id
}

func (validator *WebAuthnValidator) Update() error {
	db, err := GetDatabase()
	if err != nil {
		return err
	}

	authenticator, err := validator.SerializeAuthenticator()
	if err != nil {
		return err
	}

	err = db.Updates(authenticator).Error
	if err != nil {
		return err
	}

	return nil
}
