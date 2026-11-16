package database

import (
	"cmp"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

type OauthAuthorization struct {
	user        *User
	client      *OauthClient
	permissions []Permission
	accessType  string
}

func (o *OauthAuthorization) IssueCode(tokenServices *tokens.Services, state string, challenge *tokens.CodeChallengeState, accessType string, nonce string, auth *tokens.AuthContext) (string, error) {
	manager := tokenServices.AuthorizationCode()

	code, err := manager.New(
		tokens.AuthorizationCodeContent{
			UserID:   o.user.ID.String(),
			ClientID: o.client.ApplicationID.String(),
			Permissions: utils.Map(o.permissions, func(p Permission) string {
				return p.ID.String()
			}),
			State:              state,
			CodeChallengeState: challenge,
			AccessType:         accessType,
			Nonce:              nonce,
			Auth:               auth,
		})

	if err != nil {
		return "", err
	}

	return code, nil
}

func (o *OauthAuthorization) IssueLog(requestIP string) (*ApplicationConsentLog, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}

	res := ApplicationConsentLog{
		User:          *o.user,
		UserID:        o.user.ID,
		ApplicationID: o.client.ApplicationID,
		ConsentedAt:   time.Now(),
		Permissions:   o.permissions,
		ConsentIP:     requestIP,
	}

	// issue token
	err = db.Create(&res).Error
	if err != nil {
		return nil, err
	}

	// return token
	return &res, nil
}

func (l *ApplicationConsentLog) IssueAccessTokenWithGrantType(tokenServices *tokens.Services, grantType string) (string, error) {
	manager := tokenServices.AccessToken()
	permissionIDs := utils.Map(l.Permissions, func(p Permission) string {
		return p.ID.String()
	})
	if len(permissionIDs) == 0 {
		permissionIDs = nil
	}

	scopes := utils.Map(l.Permissions, func(p Permission) string {
		return p.Scope
	})
	scope := strings.Join(scopes, " ")

	var audience []string
	if l.ApplicationID != uuid.Nil {
		audience = []string{l.ApplicationID.String()}
	}

	return manager.New(tokens.AccessTokenContent{
		UserID:       l.UserID.String(),
		ClientID:     l.ApplicationID.String(),
		Permissions:  permissionIDs,
		ConsentLogID: l.ID.String(),
		GrantType:    grantType,
		Audience:     audience,
		Scope:        scope,
	})
}

func (l *ApplicationConsentLog) IssueRefreshToken(tokenServices *tokens.Services) (string, error) {
	manager := tokenServices.RefreshToken()
	permissionIDs := utils.Map(l.Permissions, func(p Permission) string {
		return p.ID.String()
	})
	if len(permissionIDs) == 0 {
		permissionIDs = nil
	}

	return manager.New(tokens.RefreshTokenContent{
		UserID:       l.UserID.String(),
		ClientID:     l.ApplicationID.String(),
		Permissions:  permissionIDs,
		ConsentLogID: l.ID.String(),
	})
}

func (l *ApplicationConsentLog) GenerateIDTokenContent(nonce string) tokens.IDTokenContent {
	content := tokens.IDTokenContent{
		Claims: jwt.Claims{
			Subject: l.User.ID.String(),
		},
		IDTokenPayload: tokens.IDTokenPayload{
			ConsentLogID: l.ID.String(),
			Scope: strings.Join(utils.Map(l.Permissions, func(p Permission) string {
				return p.Scope
			}), " "),
			Nonce: nonce,
		},
	}

	if l.HasEmailPermissions() {
		email := l.User.GetPrimaryEmail()
		emailVerified := l.User.IsEmailVerified(email)

		content.Email = &email
		content.EmailVerified = &emailVerified
	}

	if l.HasPhonePermissions() {
		phone := l.User.GetPrimaryPhone()
		phoneVerified := l.User.IsPhoneVerified(phone)

		content.PhoneNumber = &phone
		content.PhoneVerified = &phoneVerified
	}

	if l.HasProfilePermissions() {
		if usernames := l.User.GetUsernames(); len(usernames) > 0 {
			content.PreferredUsername = usernames[0]
		}

		content.GivenName = l.User.UserData.FirstName
		content.FamilyName = l.User.UserData.LastName
		content.Name = cmp.Or(l.User.UserData.DisplayName, l.User.UserData.Name, content.PreferredUsername)

		content.Picture = l.User.GetProfileURL()
		content.Profile = l.User.GetProfileURL()
		content.Locale = l.User.UserData.Language
		content.ZoneInfo = l.User.UserData.Timezone
	}

	return content
}

func (l *ApplicationConsentLog) IssueIDToken(tokenServices *tokens.Services, nonce string, auth *tokens.AuthContext) (string, error) {
	content := l.GenerateIDTokenContent(nonce)
	if auth != nil {
		content.SID, content.AuthTime, content.AMR, content.ACR = auth.SID, auth.AuthTime, auth.AMR, auth.ACR
	}
	return tokens.GenerateIDToken(tokenServices, l.ApplicationID.String(), content)
}

func (l *ApplicationConsentLog) IssueTokensWithGrantType(tokenServices *tokens.Services, accessType string, grantType string) (accessToken string, refreshToken string, err error) {
	accessToken, err = l.IssueAccessTokenWithGrantType(tokenServices, grantType)
	if err != nil {
		return "", "", err
	}

	if accessType == "offline" {
		refreshToken, err = l.IssueRefreshToken(tokenServices)
		if err != nil {
			return "", "", err
		}
	}

	return accessToken, refreshToken, nil
}
