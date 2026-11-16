package api

import (
	"context"
	"errors"
	"net/mail"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/auth"
	"github.com/meili-NG/meiliNG/v2/pkg/common"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/notify"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"gorm.io/gorm"
)

// SignInRequest represents a sign-in request
type SignInRequest struct {
	Config         *config.MeilingConfig
	TokenServices  *tokens.Services
	Session        *tokens.SessionPayload
	SignInLogData  *SignInLogData
	Username       string
	ID             string
	ChallengeToken string
	UseWebAuthn    bool
}

// SignInResult represents the result of a sign-in attempt
type SignInResult struct {
	RequiresChallenge bool
	ChallengeToken    string
	Success           bool
	UserID            *uuid.UUID
}

func ensureSignInUserActive(user *database.User) error {
	if user == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "user not found")
	}
	if user.DeletedAt != nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "user not found")
	}
	return nil
}

// SignIn handles user sign-in flow
func SignIn(req *SignInRequest) (*SignInResult, error) {
	cfg := req.Config
	if cfg == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "config required")
	}
	if req.TokenServices == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	tokenServices := req.TokenServices
	challengeManager := tokenServices.Challenge()
	sessionManager := tokenServices.Session()

	var user *database.User
	if req.ChallengeToken == "" {
		content := tokens.ChallengeContent{
			PassedChallenges: []string{},
		}

		if req.Username != "" || req.ID != "" {
			userID := req.ID
			if req.Username != "" {
				id, err := auth.IdentifierResolver.Get()(context.Background(), cfg, req.Username)
				if err != nil {
					return nil, meilingErrors.NewInternalServerError("failed to find user", err)
				}
				userID = id.String()
			}
			if userID != uuid.Nil.String() {
				var userData database.User
				db, err := database.GetUserDB()
				if err != nil {
					return nil, meilingErrors.NewInternalServerError("failed to get database", err)
				}
				if err := db.First(&userData, "id = ?", userID).Error; err == nil {
					user = &userData
				} else if !errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, meilingErrors.NewInternalServerError("failed to find user", err)
				}
			}

			if user == nil {
				return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "invalid username or email")
			}
			if err := ensureSignInUserActive(user); err != nil {
				return nil, err
			}

			content.UserID = user.ID.String()
		} else if req.UseWebAuthn {
			if !auth.PasskeyEnabled(cfg) {
				return nil, meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "passkey sign-in is disabled")
			}
			content.IsWebAuthnFlow = true
		} else {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "username or id required")
		}

		token, err := challengeManager.New(content)
		if err != nil {
			return nil, meilingErrors.NewInternalServerError("failed to create challenge", err)
		}

		return &SignInResult{
			RequiresChallenge: true,
			ChallengeToken:    token,
		}, nil
	}

	// Handle challenge token validation
	challenge, err := challengeManager.Get(req.ChallengeToken)
	if err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid challenge token")
	}

	db, err := database.GetUserDB()
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to get database", err)
	}

	var userData database.User
	err = db.First(&userData, "id = ?", challenge.UserID).Error
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to find user", err)
	}

	if userData.ID == uuid.Nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "user not found")
	}
	if err := ensureSignInUserActive(&userData); err != nil {
		return nil, err
	}
	user = &userData

	db2, err := database.GetDatabase()
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to get database", err)
	}

	var passedChallenges []database.UserAuthenticator
	if err := db2.Where("id IN ? AND user_id = ?", challenge.PassedChallenges, userData.ID).Find(&passedChallenges).Error; err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to load passed challenges", err)
	}
	passedChallenges = enabledAuthenticators(cfg, passedChallenges)

	if len(passedChallenges) == 0 {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "no challenge passed")
	}

	passedSignIn, passedTwoFactor := checkPasses(passedChallenges)
	if !passedSignIn {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "no challenge passed for signing in")
	}

	attempt := auth.SignInAttempt{
		UserID:           user.ID,
		TwoFactorEnabled: user.TwoFactorEnabled,
		Methods:          utils.Map(passedChallenges, func(a database.UserAuthenticator) string { return a.Type }),
		PassedTwoFactor:  passedTwoFactor,
	}
	if log := req.SignInLogData; log != nil {
		attempt.IP, attempt.Country, attempt.CountryCode, attempt.UserAgent = log.IP, log.Country, log.CountryCode, log.UserAgent
	}
	if err := auth.SignInPolicy.Get()(context.Background(), cfg, attempt); errors.Is(err, auth.ErrTwoFactorRequired) {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrTwoFactorRequired, "no challenge passed for two factor")
	} else if err != nil {
		var meilingErr *meilingErrors.Error
		if errors.As(err, &meilingErr) {
			return nil, err
		}
		return nil, meilingErrors.Wrap(meilingErrors.ErrAccessDenied, "sign-in refused", err)
	}

	// Sign in
	if req.Session != nil {
		req.Session.SignIn(user.ID.String())
		req.Session.RecordSignIn(user.ID.String(), tokens.UserAuth{
			Time:      time.Now().Unix(),
			Methods:   attempt.Methods,
			TwoFactor: attempt.PassedTwoFactor,
		})
		err = req.Session.Update(sessionManager)
		if err != nil {
			return nil, meilingErrors.NewInternalServerError("failed to update session", err)
		}
	}

	err = challengeManager.Revoke(req.ChallengeToken)
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to revoke challenge", err)
	}

	if req.Session != nil {
		_ = MarkSignIn(req.Session, req.SignInLogData, user.ID)
	}

	return &SignInResult{Success: true, UserID: &user.ID}, nil
}

// SignOutRequest represents a sign-out request
type SignOutRequest struct {
	TokenServices *tokens.Services
	Session       *tokens.SessionPayload
}

// SignOutResult represents the result of sign-out
type SignOutResult struct {
	UserIDs []uuid.UUID
	// FrontchannelLogoutURIs are the applications' front-channel logout URIs
	// for the browser to load.
	FrontchannelLogoutURIs []string
}

// SignOut signs out all users from the session
func SignOut(req *SignOutRequest) (*SignOutResult, error) {
	if req.Session == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session required")
	}
	if req.TokenServices == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	userIds := utils.Map(req.Session.Users, func(id string) uuid.UUID {
		return uuid.MustParse(id)
	})

	signedIn := slices.Clone(req.Session.Users)
	req.Session.SignOutAll()
	err := req.Session.Update(req.TokenServices.Session())
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to update session", err)
	}

	return &SignOutResult{
		UserIDs:                userIds,
		FrontchannelLogoutURIs: endApplicationSessions(req.TokenServices, req.Session.SID, signedIn),
	}, nil
}

// IForgotRequest represents a password reset request
type IForgotRequest struct {
	TokenServices  *tokens.Services
	Username       string
	OwnershipToken string
	Password       string
}

// IForgot handles password reset via ownership token
func IForgot(req *IForgotRequest) error {
	if req.Username == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "username required")
	}

	if req.OwnershipToken == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "ownership token required")
	}
	if req.TokenServices == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	manager := req.TokenServices.Ownership()
	token, err := manager.Get(req.OwnershipToken)
	if err != nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid ownership token")
	}

	userID, err := auth.IdentifierResolver.Get()(context.Background(), req.TokenServices.Config(), req.Username)
	if err != nil {
		return meilingErrors.NewInternalServerError("failed to find user", err)
	}
	var user *database.User
	if userID != uuid.Nil {
		if user, err = findUserByID(userID.String()); err != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "user not found")
		}
	}
	if user == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "user not found")
	}

	if token.Email == "" && token.Phone == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid ownership token")
	}

	if token.Email != "" && !token.IsAnyOfEmailVerified(user.GetVerifiedEmails()...) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid email")
	} else if token.Phone != "" && !token.IsAnyOfPhoneVerified(user.GetVerifiedPhones()...) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid phone")
	}

	if !validator.IsValidPassword(req.Password) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid password")
	}

	err = user.SetPassword(req.Password)
	if err != nil {
		return meilingErrors.NewInternalServerError("failed to set password", err)
	}

	if req.OwnershipToken != "" {
		_ = manager.Revoke(req.OwnershipToken)
	}
	return nil
}

// SignUpConfig represents the sign-up configuration
type SignUpConfig struct {
	AllowSignUp               bool
	EmailRequired             bool
	PhoneRequired             bool
	UsernameRequired          bool
	EmailVerificationRequired bool
	PhoneVerificationRequired bool
}

// GetSignUpConfig returns the current sign-up configuration
func GetSignUpConfig(cfg *config.MeilingConfig) (*SignUpConfig, error) {
	if cfg == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "config required")
	}

	return &SignUpConfig{
		AllowSignUp:               cfg.AuthConfig.SignUp.AllowSignUp,
		EmailRequired:             cfg.AuthConfig.SignUp.EmailRequired,
		PhoneRequired:             cfg.AuthConfig.SignUp.PhoneRequired,
		UsernameRequired:          cfg.AuthConfig.SignUp.UsernameRequired,
		EmailVerificationRequired: cfg.AuthConfig.SignUp.EmailVerificationRequired,
		PhoneVerificationRequired: cfg.AuthConfig.SignUp.PhoneVerificationRequired,
	}, nil
}

// OwnershipVerifyRequest represents an ownership verification request
type OwnershipVerifyRequest struct {
	Config         *config.MeilingConfig
	TokenServices  *tokens.Services
	Email          string
	Phone          string
	OwnershipToken string
	Response       string
	Language       string
}

// OwnershipVerify handles ownership verification for sign-up
func OwnershipVerify(req *OwnershipVerifyRequest) (string, error) {
	cfg := req.Config
	if cfg == nil {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "config required")
	}
	if req.TokenServices == nil {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	if !cfg.AuthConfig.SignUp.AllowSignUp {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "signup is disabled")
	}

	manager := req.TokenServices.Ownership()

	// Verification Response
	if req.OwnershipToken != "" && req.Response != "" {
		token := req.OwnershipToken

		content, err := manager.Get(token)
		if err != nil {
			return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid token")
		}

		if content.VerifyEmailChallenge(req.Email, req.Response) {
			content.EmailVerified = true
			err = manager.Set(token, content)
			if err != nil {
				return "", meilingErrors.NewInternalServerError("failed to set token", err)
			}
		} else if content.VerifyPhoneChallenge(generalizedPhone(cfg, req.Phone), req.Response) {
			content.PhoneVerified = true
			err = manager.Set(token, content)
			if err != nil {
				return "", meilingErrors.NewInternalServerError("failed to set token", err)
			}
		} else {
			return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid response")
		}

		return token, nil
	}

	// Verification Request
	var content tokens.OwnershipTokenContent
	token := req.OwnershipToken

	if token != "" {
		var err error
		content, err = manager.Get(token)
		if err != nil {
			return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid token")
		}
	}

	email := req.Email
	phone := req.Phone

	if email != "" {
		if _, err := mail.ParseAddress(email); err != nil {
			return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid email")
		}
	} else if phone != "" {
		num, err := common.GeneralizePhone(cfg, phone)
		if err != nil {
			return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid phone")
		}
		phone = num
	}

	if email == "" && phone == "" {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "email or phone required")
	}

	challenge := utils.RandomStringWithCharset(6, "0123456789")
	if email != "" {
		content.SetEmailChallengeWithDuration(email, challenge, manager.ChallengeDuration())
		if err := common.SendVerificationCode(cfg, email, challenge, req.Language); err != nil {
			return "", meilingErrors.NewInternalServerError("failed to send verification code", err)
		}
	} else if phone != "" {
		if _, err := notify.ResolveProvider(cfg, notify.NotifyKeyPhoneVerificationCode); err != nil {
			return "", meilingErrors.NewMeilingError(meilingErrors.ErrNotImplemented, "phone verification is not configured")
		}
		content.SetPhoneChallengeWithDuration(phone, challenge, manager.ChallengeDuration())
		if err := common.SendPhoneVerificationCode(cfg, phone, challenge, req.Language); err != nil {
			return "", meilingErrors.NewInternalServerError("failed to send verification code", err)
		}
	}

	if req.OwnershipToken != "" {
		if err := manager.Set(token, content); err != nil {
			return "", meilingErrors.NewInternalServerError("failed to set token", err)
		}
	} else {
		var err error
		token, err = manager.New(content)
		if err != nil {
			return "", meilingErrors.NewInternalServerError("failed to create token", err)
		}
	}

	return token, nil
}

// SignUpRequest represents a sign-up request
type SignUpRequest struct {
	Config         *config.MeilingConfig
	TokenServices  *tokens.Services
	Email          string
	Phone          string
	OwnershipToken string
	Username       string
	Password       string
	Name           string
}

// SignUp creates a new user account
func SignUp(req *SignUpRequest) error {
	cfg := req.Config
	if cfg == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "config required")
	}
	if req.TokenServices == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	if !cfg.AuthConfig.SignUp.AllowSignUp {
		return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "signup is disabled")
	}

	emailVerified := false
	phoneVerified := false
	email := req.Email
	phone := req.Phone

	manager := req.TokenServices.Ownership()
	if cfg.AuthConfig.SignUp.EmailVerificationRequired || cfg.AuthConfig.SignUp.PhoneVerificationRequired {
		if req.OwnershipToken == "" {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "signup token required")
		}

		token, err := manager.Get(req.OwnershipToken)
		if err != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid token")
		}

		email = token.Email
		phone = token.Phone

		if cfg.AuthConfig.SignUp.EmailVerificationRequired && !token.IsEmailVerified(email) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "email not verified")
		} else if token.IsEmailVerified(email) {
			emailVerified = true
		}

		if cfg.AuthConfig.SignUp.PhoneVerificationRequired && !token.IsPhoneVerified(phone) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "phone not verified")
		} else if token.IsPhoneVerified(phone) {
			phoneVerified = true
		}
	}

	if email == "" && cfg.AuthConfig.SignUp.EmailRequired {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "email required")
	}

	if phone == "" && cfg.AuthConfig.SignUp.PhoneRequired {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "phone required")
	}

	finder := database.UserFinder{}
	if !cfg.AuthConfig.SignUp.AllowDuplicateEmail {
		existingUser, err := finder.FindByEmail(email, false)
		if err != nil {
			return meilingErrors.NewInternalServerError("failed to check email", err)
		}
		if existingUser != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrDuplicateEmail, "email already exists")
		}
	}

	user, err := database.NewUser()
	if err != nil {
		return meilingErrors.NewInternalServerError("failed to create user", err)
	}

	err = user.AddPassword(req.Password)
	if err != nil {
		return meilingErrors.NewInternalServerError("failed to add password", err)
	}

	if req.Username != "" {
		u, err := finder.FindByUserName(req.Username)
		if err != nil {
			return meilingErrors.NewInternalServerError("failed to check username", err)
		}

		if u != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrDuplicateUsername, "username already exists")
		}

		if !validator.IsValidUsername(req.Username) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid username")
		}

		user.UserNames = append(user.UserNames, database.UserName{
			UserNameFields: models.UserNameFields{
				Username: req.Username,
			},
		})
	}

	if email != "" {
		err = user.AddEmail(email, emailVerified)
		if err != nil {
			return meilingErrors.NewInternalServerError("failed to add email", err)
		}
	}

	if phone != "" {
		err = user.AddPhone(phone, phoneVerified)
		if err != nil {
			return meilingErrors.NewInternalServerError("failed to add phone", err)
		}
	}

	if req.Name != "" {
		user.UserData.UserID = user.ID
		user.UserData.Name = req.Name
	}

	db, err := database.GetUserDB()
	if err != nil {
		return meilingErrors.NewInternalServerError("failed to get database", err)
	}

	res := db.Create(user)
	if res.Error != nil {
		return meilingErrors.NewInternalServerError("failed to create user", res.Error)
	}

	if req.OwnershipToken != "" {
		_ = manager.Revoke(req.OwnershipToken)
	}
	return nil
}

// checkPasses evaluates which authentication challenges have been passed
func checkPasses(challenge []database.UserAuthenticator) (passedSignIn bool, passedTwoFactor bool) {
	passedSignIn = false
	passedTwoFactor = false

	for _, c := range challenge {
		if c.AllowSignIn {
			passedSignIn = true
		}

		if c.Allow2FA {
			passedTwoFactor = true
		}

		if c.AllowPasswordless {
			passedSignIn = true
			passedTwoFactor = true
		}
	}

	return passedSignIn, passedTwoFactor
}

// generalizedPhone returns phone in the form a phone challenge was stored in,
// or phone unchanged when it does not parse.
func generalizedPhone(cfg *config.MeilingConfig, phone string) string {
	if num, err := common.GeneralizePhone(cfg, phone); err == nil {
		return num
	}
	return phone
}

// enabledAuthenticators drops authenticators whose type auth.signin disables.
func enabledAuthenticators(cfg *config.MeilingConfig, authenticators []database.UserAuthenticator) []database.UserAuthenticator {
	return utils.Filter(authenticators, func(a database.UserAuthenticator) bool {
		return auth.MethodEnabled(cfg, a.Type)
	})
}
