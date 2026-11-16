package api

import (
	"strings"

	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/server/webui"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

type SelectedUser struct {
	ID string
}

func ResolveSelectedUser(caller *tokens.Principal, userID string) (*SelectedUser, error) {
	if err := ValidateUserSessionAccess(caller, userID); err != nil {
		return nil, err
	}

	return &SelectedUser{ID: userID}, nil
}

// ParseAuthorization resolves an Authorization header to the principal
// calling: a session, or an admin token.
func ParseAuthorization(cfg *config.MeilingConfig, tokenServices *tokens.Services, authorization string) (*tokens.Principal, error) {
	if authorization == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "authorization header is required")
	}

	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "invalid authorization header")
	}

	method := parts[0]
	token := parts[1]
	if tokens.IsSessionScheme(method) {
		method = "Bearer"
	}

	if strings.EqualFold(method, "Bearer") {
		// Check token type before assuming session token
		jwt := tokenServices.JWT()
		privateClaims, err := jwt.ParseTokenPrivateClaims(token)
		if err != nil {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidToken, "failed to parse token")
		}

		if privateClaims.TokenType == tokens.TokenTypeAccessToken {
			// TODO: implement M2M authentication via OAuth2 access tokens
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "M2M access token authentication is not yet supported")
		}

		sessionManager := tokenServices.Session()
		payload, err := sessionManager.Get(token)
		if err != nil || !payload.IsNotBlank() || !payload.IsValid(sessionManager) {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "invalid token")
		}
		if err := PruneInactiveSessionUsers(&payload, sessionManager); err != nil {
			return nil, err
		}
		return tokens.SessionPrincipal(&payload), nil
	}

	if cfg != nil && strings.EqualFold(method, cfg.AdminConfig.AdminTokenMethod) {
		if principal := webui.AdminPrincipal(cfg, tokenServices, token); principal != nil {
			return principal, nil
		}
	}

	return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "unsupported authorization method")
}

func PruneInactiveSessionUsers(session *tokens.SessionPayload, manager *tokens.SessionManager) error {
	if session == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session is not valid")
	}
	if len(session.Users) == 0 {
		return nil
	}

	activeUsers, err := activeUserIDSet(session.Users)
	if err != nil {
		return err
	}

	changed := false
	seen := make(map[string]struct{}, len(session.Users))
	activeSessionUsers := make([]string, 0, len(session.Users))
	for _, rawUserID := range session.Users {
		userID := strings.TrimSpace(rawUserID)
		if userID == "" {
			changed = true
			continue
		}
		if _, ok := seen[userID]; ok {
			changed = true
			continue
		}
		seen[userID] = struct{}{}
		if _, ok := activeUsers[userID]; !ok {
			changed = true
			continue
		}
		if userID != rawUserID {
			changed = true
		}
		activeSessionUsers = append(activeSessionUsers, userID)
	}

	if !changed {
		return nil
	}
	if manager == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "session manager required")
	}

	session.Users = activeSessionUsers
	return session.Update(manager)
}

func activeUserIDSet(userIDs []string) (map[string]struct{}, error) {
	ids := make([]string, 0, len(userIDs))
	seen := make(map[string]struct{}, len(userIDs))
	for _, rawUserID := range userIDs {
		userID := strings.TrimSpace(rawUserID)
		if userID == "" {
			continue
		}
		if _, ok := seen[userID]; ok {
			continue
		}
		seen[userID] = struct{}{}
		ids = append(ids, userID)
	}

	active := make(map[string]struct{}, len(ids))
	if len(ids) == 0 {
		return active, nil
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}

	var users []database.User
	if err := db.Select("id").Where("id IN ? AND deleted_at IS NULL", ids).Find(&users).Error; err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to validate session users", err)
	}
	for _, user := range users {
		active[user.ID.String()] = struct{}{}
	}

	return active, nil
}

func ValidateUserSessionAccess(caller *tokens.Principal, userID string) error {
	if caller == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "caller is not valid")
	}
	if userID == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user_id is required")
	}
	if !caller.IsAdmin() && !caller.HasUser(userID) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "you are not allowed to access this user")
	}

	_, err := findUserByID(userID)
	return err
}

func ListPublicPermissions() ([]types.PermissionSerialized, error) {
	db, err := getDB()
	if err != nil {
		return nil, err
	}

	var permissions []database.Permission
	if err := db.Find(&permissions, "is_public = true").Error; err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to list permissions", err)
	}

	return utils.Map(permissions, func(permission database.Permission) types.PermissionSerialized {
		return permission.Serialize()
	}), nil
}

// requireSession returns caller's session, refusing admin credentials: they
// act on users but have no session to sign users into or out of.
func requireSession(caller *tokens.Principal) (*tokens.SessionPayload, error) {
	if caller == nil || caller.Session == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "this needs a session; admin credentials have none")
	}
	return caller.Session, nil
}
