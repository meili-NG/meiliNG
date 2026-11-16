package api

import (
	"errors"
	"github.com/meili-NG/meiliNG/v2/pkg/metadata"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/geoip"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/common"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ListUsersRequest struct {
	Caller     *tokens.Principal
	Pagination *PaginationDetail
	All        bool
	Search     string
}

type CreateUserRequest struct {
	Emails   []types.AddEmailRequest
	Phones   []types.AddPhoneRequest
	Password string
	Username string
}

type UpdateManagedUserRequest struct {
	Caller           *tokens.Principal
	UserID           string
	TwoFactorEnabled *bool
	MaxApplications  *int
}

type DeleteManagedUserRequest struct {
	TokenServices *tokens.Services
	Caller        *tokens.Principal
	UserID        string
}

type SignOutManagedUserRequest struct {
	TokenServices *tokens.Services
	Caller        *tokens.Principal
	UserID        string
}

type ListSigninLogsRequest struct {
	TokenServices *tokens.Services
	Caller        *tokens.Principal
	UserID        string
	Country       string
	Pagination    *PaginationDetail
}

type GetSigninLogStatisticsRequest struct {
	Caller *tokens.Principal
	UserID string
	From   string
	To     string
}

type ForceSignOutUsersRequest struct {
	TokenServices *tokens.Services
	Caller        *tokens.Principal
	UserID        string
	ID            string
}

type ChangeUserPasswordRequest struct {
	Caller           *tokens.Principal
	UserID           string
	PreviousPassword string
	NewPassword      string
}

type VerifyUserEmailRequest struct {
	Config         *config.MeilingConfig
	TokenServices  *tokens.Services
	Caller         *tokens.Principal
	UserID         string
	Email          string
	AcceptLanguage string
	Body           types.VerifyEmailRequest
}

type AddUserTOTPRequest struct {
	Config        *config.MeilingConfig
	TokenServices *tokens.Services
	Caller        *tokens.Principal
	UserID        string
	Body          types.AddTOTPRequest
}

type RegenerateUserBackupCodesRequest struct {
	Config *config.MeilingConfig
	Caller *tokens.Principal
	UserID string
}

type AddUserWebAuthnRequest struct {
	TokenServices *tokens.Services
	Caller        *tokens.Principal
	UserID        string
	Body          types.AddWebAuthnRequest
}

type UpdateUserDataRequest struct {
	Caller *tokens.Principal
	UserID string
	Body   types.UpdateUserDataRequest
}

func ListUsers(req ListUsersRequest) ([]types.UserSerialized, error) {
	result, err := ListUsersPaginated(req)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func ListUsersPaginated(req ListUsersRequest) (types.PaginatedUserSerialized, error) {
	if req.Caller == nil {
		return types.PaginatedUserSerialized{}, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session required")
	}

	q := "1=1"
	args := make([]any, 0, 7)
	if !req.Caller.IsAdmin() || !req.All {
		q = "id IN ?"
		args = append(args, req.Caller.Users())
	}

	if req.Search != "" {
		searchTerm := "%" + req.Search + "%"
		q += ` AND (
    CAST(id AS VARCHAR(36)) LIKE ? OR
    id IN (SELECT user_id FROM user_emails WHERE LOWER(email) LIKE LOWER(?)) OR
    id IN (SELECT user_id FROM user_phones WHERE phone LIKE ?) OR
    id IN (
        SELECT user_id FROM user_data
        WHERE LOWER(name) LIKE LOWER(?) OR LOWER(display_name) LIKE LOWER(?)
    ) OR
    id IN (SELECT user_id FROM user_names WHERE LOWER(username) LIKE LOWER(?))
)`
		args = append(args, utils.Repeat[any](searchTerm, 6)...)
	}

	pagination, err := buildPaginationRequest(req.Pagination)
	if err != nil {
		return types.PaginatedUserSerialized{}, err
	}

	db, err := getUserDB()
	if err != nil {
		return types.PaginatedUserSerialized{}, err
	}

	return types.GetPaginatedResultSerialized(db, pagination, func(user database.User) types.UserSerialized {
		return user.Serialize()
	}, q, args...), nil
}

func CreateUser(req CreateUserRequest) (string, error) {
	db, err := getDB()
	if err != nil {
		return "", err
	}

	user, err := database.NewUser()
	if err != nil {
		return "", meilingErrors.NewInternalServerError("failed to create user", err)
	}

	for _, email := range req.Emails {
		if err := user.AddEmail(email.Email, email.Verified); err != nil {
			return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
		}
	}

	for _, phone := range req.Phones {
		if err := user.AddPhone(phone.Phone, phone.Verified); err != nil {
			return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
		}
	}

	if req.Password != "" {
		passwordAuthn, err := database.NewPasswordAuthenticator(req.Password)
		if err != nil {
			return "", meilingErrors.NewInternalServerError("failed to create password authenticator", err)
		}

		authenticator, err := passwordAuthn.SerializeAuthenticator()
		if err != nil {
			return "", meilingErrors.NewInternalServerError("failed to serialize authenticator", err)
		}

		user.AddAuthenticator(authenticator)
	}

	if req.Username != "" {
		if err := user.AddUserName(req.Username); err != nil {
			return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
		}
	}

	if err := db.Create(user).Error; err != nil {
		return "", meilingErrors.NewInternalServerError("failed to create user", err)
	}

	return user.ID.String(), nil
}

func GetUserSerialized(caller *tokens.Principal, userID string) (types.UserSerialized, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return types.UserSerialized{}, err
	}

	if err := ensureUserDataExists(user); err != nil {
		return types.UserSerialized{}, err
	}

	return user.Serialize(), nil
}

// BulkCheckUsers looks up multiple users by ID in a single query, scoped to
// what the session is allowed to access. It returns the serialized users that
// were found and accessible, along with the list of requested IDs that were
// not found (or not accessible to the session).
func BulkCheckUsers(caller *tokens.Principal, userIDs []string) (types.BulkCheckUsersResponse, error) {
	if caller == nil {
		return types.BulkCheckUsersResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "caller required")
	}

	if len(userIDs) == 0 {
		return types.BulkCheckUsersResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "userIds is required")
	}

	// Deduplicate while keeping only IDs the caller is allowed to access.
	seen := make(map[string]struct{}, len(userIDs))
	allowed := make([]string, 0, len(userIDs))
	for _, id := range userIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if caller.HasUser(id) {
			allowed = append(allowed, id)
		}
	}

	found := make(map[string]struct{}, len(allowed))
	result := types.BulkCheckUsersResponse{
		Users:    []types.UserSerialized{},
		NotFound: []string{},
	}

	if len(allowed) > 0 {
		db, err := getUserDB()
		if err != nil {
			return types.BulkCheckUsersResponse{}, err
		}

		var users []database.User
		if err := db.Where("id IN ?", allowed).Find(&users).Error; err != nil {
			return types.BulkCheckUsersResponse{}, meilingErrors.NewInternalServerError("failed to find users", err)
		}

		for i := range users {
			found[users[i].ID.String()] = struct{}{}
			result.Users = append(result.Users, users[i].Serialize())
		}
	}

	// Anything requested (deduplicated) that wasn't returned is not found or
	// not accessible to the caller.
	for id := range seen {
		if _, ok := found[id]; !ok {
			result.NotFound = append(result.NotFound, id)
		}
	}

	return result, nil
}

func UpdateManagedUser(req UpdateManagedUserRequest) error {
	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return err
	}

	if req.MaxApplications != nil {
		if !req.Caller.IsAdmin() {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "only an admin can change maxApplications")
		}
		var limit *int
		if *req.MaxApplications >= 0 {
			limit = req.MaxApplications
		}
		db, err := getDB()
		if err != nil {
			return err
		}
		if err := db.Model(user).Update("max_applications", limit).Error; err != nil {
			return meilingErrors.NewInternalServerError("failed to update user", err)
		}
	}

	if req.TwoFactorEnabled == nil {
		return nil
	}

	user.TwoFactorEnabled = *req.TwoFactorEnabled
	if user.TwoFactorEnabled && !user.HasTwoFactorAuthn() {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "there is no two factor authenticator")
	}
	if !user.TwoFactorEnabled {
		if err := user.DisableTwoFactor(); err != nil {
			return meilingErrors.NewInternalServerError("failed to disable two factor", err)
		}
		return nil
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	if err := db.Model(user).Updates(utils.SerializeGORMColumnsToMap(*user, "TwoFactorEnabled")).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to update user", err)
	}

	return nil
}

func DeleteManagedUser(req DeleteManagedUserRequest) error {
	if req.TokenServices == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return err
	}

	if session := req.Caller.Users(); session != nil {
		req.Caller.Session.SignOut(user.ID.String())
		if err := req.Caller.Session.Update(req.TokenServices.Session()); err != nil {
			return meilingErrors.NewInternalServerError("failed to update session", err)
		}
	}

	now := time.Now()
	user.DeletedAt = &now

	db, err := getUserDB()
	if err != nil {
		return err
	}

	if err := db.Updates(user).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to delete user", err)
	}

	return nil
}

func SignOutManagedUser(req SignOutManagedUserRequest) error {
	if req.TokenServices == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return err
	}

	session, err := requireSession(req.Caller)
	if err != nil {
		return err
	}
	session.SignOut(user.ID.String())
	if err := session.Update(req.TokenServices.Session()); err != nil {
		return meilingErrors.NewInternalServerError("failed to update session", err)
	}
	// shortcut: back-channel only; this answers without a body, so no
	// front-channel URIs reach the browser.
	endApplicationSessions(req.TokenServices, session.SID, []string{user.ID.String()})

	if err := MarkSignOut(session, user.ID); err != nil {
		return meilingErrors.NewInternalServerError("failed to mark sign out", err)
	}

	return nil
}

func ListSigninLogs(req ListSigninLogsRequest) ([]types.SignInLogSerialized, error) {
	result, err := ListSigninLogsPaginated(req)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func ListSigninLogsPaginated(req ListSigninLogsRequest) (types.PaginatedSigninLogSerialized, error) {
	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return types.PaginatedSigninLogSerialized{}, err
	}

	pagination, err := buildPaginationRequest(req.Pagination)
	if err != nil {
		return types.PaginatedSigninLogSerialized{}, err
	}

	db, err := getDB()
	if err != nil {
		return types.PaginatedSigninLogSerialized{}, err
	}

	query := "user_id = ?"
	args := []any{user.ID}
	if req.Country != "" {
		query += " AND UPPER(country) = UPPER(?)"
		args = append(args, req.Country)
	}

	return types.GetOrderedPaginatedResultSerialized(db, pagination, func(log database.SignInLog) types.SignInLogSerialized {
		return serializeSigninLog(log, req.TokenServices)
	}, "signed_in_at DESC", query, args...), nil
}

type signInCountryStatisticRow struct {
	Country string
	Count   int64
}

const maxUserSigninStatisticsRange = 30 * 24 * time.Hour

func GetSigninLogStatistics(req GetSigninLogStatisticsRequest) (types.SignInStatisticsResponse, error) {
	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return types.SignInStatisticsResponse{}, err
	}

	db, err := getDB()
	if err != nil {
		return types.SignInStatisticsResponse{}, err
	}

	query := db.Model(&database.SignInLog{}).
		Select("country, COUNT(*) AS count").
		Where("user_id = ? AND country != ''", user.ID)

	query, err = applySigninLogRangeFilter(query, req.Caller, req.From, req.To)
	if err != nil {
		return types.SignInStatisticsResponse{}, err
	}

	var rows []signInCountryStatisticRow
	if err := query.Group("country").Order("count DESC, country ASC").Scan(&rows).Error; err != nil {
		return types.SignInStatisticsResponse{}, meilingErrors.NewInternalServerError("failed to get signin log statistics", err)
	}

	return types.SignInStatisticsResponse{
		Statistics: types.SignInStatisticsSerialized{
			Countries: utils.Map(rows, func(row signInCountryStatisticRow) types.SignInCountryStatisticSerialized {
				countryCode := geoip.NormalizeCountryCode(row.Country)
				countryName := geoip.CountryName(countryCode)
				if countryName == "" {
					countryName = strings.TrimSpace(row.Country)
				}
				return types.SignInCountryStatisticSerialized{
					Country:     countryName,
					CountryCode: countryCode,
					Count:       row.Count,
				}
			}),
		},
	}, nil
}

func GetFirstSigninLog(tokenServices *tokens.Services, caller *tokens.Principal, userID string) (types.SignInLogSerialized, error) {
	return getSigninLogByOrder(tokenServices, caller, userID, "signed_in_at ASC")
}

func GetLatestSigninLog(tokenServices *tokens.Services, caller *tokens.Principal, userID string) (types.SignInLogSerialized, error) {
	return getSigninLogByOrder(tokenServices, caller, userID, "signed_in_at DESC")
}

func GetCurrentSigninLog(tokenServices *tokens.Services, caller *tokens.Principal, userID string) (types.SignInLogSerialized, error) {
	if caller == nil || caller.IsAdmin() || !caller.HasUser(userID) {
		return types.SignInLogSerialized{}, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "user caller required")
	}

	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return types.SignInLogSerialized{}, err
	}

	db, err := getDB()
	if err != nil {
		return types.SignInLogSerialized{}, err
	}

	session, err := requireSession(caller)
	if err != nil {
		return types.SignInLogSerialized{}, err
	}

	var log database.SignInLog
	if err := db.Order("signed_in_at DESC").First(&log, "user_id = ? AND session_id = ?", user.ID, session.GetSID()).Error; err != nil {
		return types.SignInLogSerialized{}, handleSigninLogLookupError("current signin log not found", err)
	}

	return serializeSigninLog(log, tokenServices), nil
}

func getSigninLogByOrder(tokenServices *tokens.Services, caller *tokens.Principal, userID string, order string) (types.SignInLogSerialized, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return types.SignInLogSerialized{}, err
	}

	db, err := getDB()
	if err != nil {
		return types.SignInLogSerialized{}, err
	}

	var log database.SignInLog
	if err := db.Order(order).First(&log, "user_id = ?", user.ID).Error; err != nil {
		return types.SignInLogSerialized{}, handleSigninLogLookupError("signin log not found", err)
	}

	return serializeSigninLog(log, tokenServices), nil
}

func serializeSigninLog(log database.SignInLog, tokenServices *tokens.Services) types.SignInLogSerialized {
	serialized := log.Serialize()
	countryCode := geoip.NormalizeCountryCode(serialized.Country)
	if countryCode == "" {
		countryCode = geoip.CountryCodeFromData(serialized.GeoIPData)
	}

	countryName := geoip.CountryName(countryCode)
	if countryName == "" {
		countryName = geoip.CountryNameFromData(serialized.GeoIPData)
	}
	if countryName == "" && countryCode == "" {
		countryName = strings.TrimSpace(serialized.Country)
	}

	serialized.Country = countryName
	serialized.CountryCode = countryCode

	if serialized.SignedOutAt != nil {
		return serialized
	}

	if serialized.ExpiresAt != nil && serialized.ExpiresAt.Before(time.Now()) {
		autoSignedOutAt := *serialized.ExpiresAt
		serialized.SignedOutAt = &autoSignedOutAt
		return serialized
	}

	if tokenServices == nil {
		return serialized
	}

	session, err := tokenServices.Session().GetBySID(log.SessionID.String())
	if err != nil || !session.IsExpired() || session.ExpiresAt.IsZero() {
		return serialized
	}

	expiredAt := session.ExpiresAt
	if serialized.ExpiresAt == nil {
		serialized.ExpiresAt = &expiredAt
	}
	serialized.SignedOutAt = &expiredAt
	return serialized
}

func handleSigninLogLookupError(message string, err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, message)
	}
	return meilingErrors.NewInternalServerError("failed to get signin log", err)
}

func applySigninLogRangeFilter(query *gorm.DB, caller *tokens.Principal, fromValue string, toValue string) (*gorm.DB, error) {
	from, hasFrom, err := parseSigninLogRangeBound(fromValue, "from")
	if err != nil {
		return nil, err
	}

	to, hasTo, err := parseSigninLogRangeBound(toValue, "to")
	if err != nil {
		return nil, err
	}

	if caller != nil && !caller.IsAdmin() {
		now := time.Now()
		switch {
		case !hasFrom && !hasTo:
			to = now
			from = now.Add(-maxUserSigninStatisticsRange)
			hasFrom = true
			hasTo = true
		case hasFrom && !hasTo:
			to = from.Add(maxUserSigninStatisticsRange)
			if to.After(now) {
				to = now
			}
			hasTo = true
		case !hasFrom && hasTo:
			from = to.Add(-maxUserSigninStatisticsRange)
			hasFrom = true
		}
	}

	if hasFrom && hasTo {
		if to.Before(from) {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid signin log range")
		}
		if caller != nil && !caller.IsAdmin() && to.Sub(from) > maxUserSigninStatisticsRange {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "signin log statistics range cannot exceed 30 days")
		}
	}

	if hasFrom {
		query = query.Where("signed_in_at >= ?", from)
	}
	if hasTo {
		query = query.Where("signed_in_at <= ?", to)
	}

	return query, nil
}

func parseSigninLogRangeBound(value string, label string) (time.Time, bool, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, false, nil
	}

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid "+label+" time")
	}

	return parsed, true, nil
}

func ForceSignOutUsers(req ForceSignOutUsersRequest) error {
	if req.TokenServices == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return err
	}

	q := "user_id = ?"
	args := []any{user.ID}

	if req.ID != "" {
		q += " AND id = ?"
		args = append(args, req.ID)
	} else if session := req.Caller.Session; session != nil {
		// Every session but the caller's; an admin, having none, revokes all.
		q += " AND session_id != ?"
		args = append(args, session.GetSID())
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	var logs []database.SignInLog
	if err := db.Where(q, args...).Find(&logs).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to find signin logs", err)
	}

	if len(logs) == 0 {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "signin log not found")
	}

	manager := req.TokenServices.Session()
	for _, log := range logs {
		sess, err := manager.GetBySID(log.SessionID.String())
		if err != nil {
			var merr *meilingErrors.MeilingError
			if errors.As(err, &merr) && !sess.IsNotBlank() && merr.Type == meilingErrors.ErrUnidentifiedToken {
				if log.SignedOutAt == nil {
					sess.SID = log.SessionID.String()
					if err := MarkSignOut(&sess, user.ID); err != nil {
						return meilingErrors.NewInternalServerError("failed to mark sign out", err)
					}
				}
				continue
			}

			return meilingErrors.NewInternalServerError("failed to get session", err)
		}

		sess.SignOut(user.ID.String())
		if err := sess.Update(manager); err != nil {
			return meilingErrors.NewInternalServerError("failed to update session", err)
		}

		if err := MarkSignOut(&sess, user.ID); err != nil {
			return meilingErrors.NewInternalServerError("failed to mark sign out", err)
		}
	}

	return nil
}

func ChangeUserPassword(req ChangeUserPasswordRequest) error {
	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return err
	}

	if req.Caller.IsAdmin() && req.PreviousPassword == "" {
		if err := user.SetPassword(req.NewPassword); err != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
		}
	} else if err := user.ChangePassword(req.PreviousPassword, req.NewPassword); err != nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
	}

	if err := saveUserWithAssociations(user); err != nil {
		return err
	}

	return nil
}

func mutateAccessibleUserWithAssociations(caller *tokens.Principal, userID string, mutate func(*database.User) error) error {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return err
	}

	if err := mutate(user); err != nil {
		return err
	}

	return saveUserWithAssociations(user)
}

func requireUserMutationTarget(value string, name string) error {
	if value == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, name+" is required")
	}

	return nil
}

func GetUsernames(caller *tokens.Principal, userID string) ([]string, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return nil, err
	}
	return user.GetUsernames(), nil
}

// requireUsernameMutable refuses a username change while the name is locked
// and empty, because the OIDC name claim then falls back to the username.
func requireUsernameMutable(caller *tokens.Principal, user *database.User) error {
	data := user.UserData
	if !caller.IsAdmin() && !data.AllowsUpdating("name") && data.Name == "" && data.DisplayName == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "username is locked")
	}
	return nil
}

func AddUsernameToUser(cfg *config.MeilingConfig, caller *tokens.Principal, userID string, username string) error {
	return mutateAccessibleUserWithAssociations(caller, userID, func(user *database.User) error {
		if err := requireUsernameMutable(caller, user); err != nil {
			return err
		}

		if maxUsernames := cfg.AuthConfig.SignUp.MaxUsernames; !caller.IsAdmin() && maxUsernames > 0 && len(user.GetUsernames()) >= maxUsernames {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "maximum number of usernames reached")
		}

		if err := user.AddUserName(username); err != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
		}
		return nil
	})
}

func ChangeUsernameForUser(caller *tokens.Principal, userID string, username string) error {
	return mutateAccessibleUserWithAssociations(caller, userID, func(user *database.User) error {
		if err := requireUsernameMutable(caller, user); err != nil {
			return err
		}

		if !validator.IsValidUsername(username) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid username")
		}

		if err := user.ChangeUserName(username); err != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
		}

		return nil
	})
}

func RemoveUsernameFromUser(caller *tokens.Principal, userID string, username string) error {
	return mutateAccessibleUserWithAssociations(caller, userID, func(user *database.User) error {
		if err := requireUsernameMutable(caller, user); err != nil {
			return err
		}

		if err := requireUserMutationTarget(username, "username"); err != nil {
			return err
		}

		user.RemoveUserName(username)
		return nil
	})
}

func GetUserEmails(caller *tokens.Principal, userID string) ([]types.AddEmailRequest, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return nil, err
	}
	return user.GetEmails(), nil
}

func AddEmailToUser(caller *tokens.Principal, userID, email string, verified bool) error {
	if !caller.IsAdmin() && verified {
		return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "only admin can verify email")
	}

	return mutateAccessibleUserWithAssociations(caller, userID, func(user *database.User) error {
		if err := user.AddEmail(email, verified); err != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
		}
		return nil
	})
}

func RemoveEmailFromUser(caller *tokens.Principal, userID, email string) error {
	return mutateAccessibleUserWithAssociations(caller, userID, func(user *database.User) error {
		if err := requireUserMutationTarget(email, "email"); err != nil {
			return err
		}

		user.RemoveEmail(email)
		return nil
	})
}

func UpdateUserEmail(caller *tokens.Principal, userID, email string, payload types.UpdateEmailRequest) error {
	return mutateAccessibleUserWithAssociations(caller, userID, func(user *database.User) error {
		if err := requireUserMutationTarget(email, "email"); err != nil {
			return err
		}

		if !caller.IsAdmin() && payload.Verified {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "only admin can verify email")
		}

		user.UpdateEmail(email, payload)
		return nil
	})
}

func VerifyUserEmail(req VerifyUserEmailRequest) (types.VerifyEmailResponse, error) {
	if req.TokenServices == nil {
		return types.VerifyEmailResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return types.VerifyEmailResponse{}, err
	}

	if !req.Caller.HasUser(user.ID.String()) {
		return types.VerifyEmailResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "you are not allowed to verify email")
	}

	if req.Email == "" {
		return types.VerifyEmailResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "email is required")
	}

	emails := utils.Map(user.GetEmails(), func(item types.AddEmailRequest) string {
		return item.Email
	})
	if _, found := utils.Find(emails, func(item string) bool { return item == req.Email }); !found {
		return types.VerifyEmailResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "email is not found")
	}

	manager := req.TokenServices.Verification()
	body := req.Body
	if body.Challenge == "" {
		code := utils.RandomStringWithCharset(6, "0123456789")
		if err := common.SendVerificationCode(req.Config, req.Email, code, req.AcceptLanguage); err != nil {
			return types.VerifyEmailResponse{}, meilingErrors.NewInternalServerError("failed to send verification code", err)
		}

		token, err := manager.New(tokens.VerificationMergedPayload{
			VerificationPayload: tokens.VerificationPayload{
				Email: req.Email,
			},
			VerificationServerPayload: tokens.VerificationServerPayload{
				Challenge: code,
			},
		})
		if err != nil {
			return types.VerifyEmailResponse{}, meilingErrors.NewInternalServerError("failed to create verification token", err)
		}

		return types.VerifyEmailResponse{VerificationToken: token}, nil
	}

	if body.VerificationToken == "" {
		return types.VerifyEmailResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid request")
	}

	data, err := manager.Get(body.VerificationToken)
	if err != nil {
		return types.VerifyEmailResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid verification token")
	}

	if data.Email != req.Email {
		return types.VerifyEmailResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid email")
	}

	if data.Challenge != body.Challenge {
		return types.VerifyEmailResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid challenge")
	}

	user.UpdateEmail(req.Email, types.UpdateEmailRequest{Verified: true})

	db, err := getUserDB()
	if err != nil {
		return types.VerifyEmailResponse{}, err
	}

	if err := db.Updates(user).Error; err != nil {
		return types.VerifyEmailResponse{}, meilingErrors.NewInternalServerError("failed to update user", err)
	}

	return types.VerifyEmailResponse{}, nil
}

func GetUserPhones(caller *tokens.Principal, userID string) ([]types.AddPhoneRequest, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return nil, err
	}
	return user.GetPhones(), nil
}

func AddPhoneToUser(caller *tokens.Principal, userID, phone string, verified bool) error {
	if !caller.IsAdmin() && verified {
		return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "only admin can verify phone")
	}

	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return err
	}

	if err := user.AddPhone(phone, verified); err != nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
	}

	db, err := getUserDB()
	if err != nil {
		return err
	}

	if err := db.Updates(user).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to update user", err)
	}

	return nil
}

func RemovePhoneFromUser(caller *tokens.Principal, userID, phone string) error {
	return mutateAccessibleUserWithAssociations(caller, userID, func(user *database.User) error {
		if err := requireUserMutationTarget(phone, "phone"); err != nil {
			return err
		}

		if err := user.RemovePhone(phone); err != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
		}

		return nil
	})
}

func UpdateUserPhone(caller *tokens.Principal, userID, phone string, payload types.UpdatePhoneRequest) error {
	return mutateAccessibleUserWithAssociations(caller, userID, func(user *database.User) error {
		if err := requireUserMutationTarget(phone, "phone"); err != nil {
			return err
		}

		if !caller.IsAdmin() && payload.Verified {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "only admin can verify phone")
		}

		if err := user.UpdatePhone(phone, payload); err != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, err.Error())
		}

		return nil
	})
}

func GetUserTOTP(caller *tokens.Principal, userID string) ([]types.GetTOTPResponse, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return nil, err
	}

	authenticators := user.GetAuthenticators((&database.TOTPValidator{}).Type())
	return utils.Map(authenticators, func(authenticator database.UserAuthenticator) types.GetTOTPResponse {
		return types.GetTOTPResponse{
			ID:   authenticator.ID.String(),
			Note: authenticator.Note,
		}
	}), nil
}

func AddUserTOTP(req AddUserTOTPRequest) (types.AddTOTPResponse, error) {
	if req.TokenServices == nil {
		return types.AddTOTPResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return types.AddTOTPResponse{}, err
	}

	manager := req.TokenServices.RegisterToken()
	if req.Body.Token == "" {
		opts := req.Config.AuthConfig.TOTP.GetGenerateOpts()
		opts.AccountName = user.GetPrimaryUserName()
		key, err := totp.Generate(opts)
		if err != nil {
			return types.AddTOTPResponse{}, meilingErrors.NewInternalServerError("failed to generate TOTP", err)
		}

		registerToken, err := manager.New(tokens.ResourceRegisterContent{
			TOTP: key.URL(),
		})
		if err != nil {
			return types.AddTOTPResponse{}, meilingErrors.NewInternalServerError("failed to create register token", err)
		}

		return types.AddTOTPResponse{
			TotpUrl: key.URL(),
			Token:   registerToken,
		}, nil
	}

	data, err := manager.Get(req.Body.Token)
	if err != nil {
		return types.AddTOTPResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid token")
	}

	if data.TOTP == "" {
		return types.AddTOTPResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid token")
	}

	key, err := otp.NewKeyFromURL(data.TOTP)
	if err != nil {
		return types.AddTOTPResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid TOTP URL")
	}

	if !totp.Validate(req.Body.Challenge, key.Secret()) {
		return types.AddTOTPResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid challenge")
	}

	if err := user.AddTOTP(key, req.Body.Note); err != nil {
		return types.AddTOTPResponse{}, meilingErrors.NewInternalServerError("failed to add TOTP", err)
	}

	db, err := getUserDB()
	if err != nil {
		return types.AddTOTPResponse{}, err
	}

	if err := db.Updates(user).Error; err != nil {
		return types.AddTOTPResponse{}, meilingErrors.NewInternalServerError("failed to update user", err)
	}

	return types.AddTOTPResponse{}, nil
}

func RemoveUserTOTP(caller *tokens.Principal, userID, totpID string) error {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return err
	}

	if totpID == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "totp_id is required")
	}

	authenticator, found := utils.Find(user.Authenticators, func(item database.UserAuthenticator) bool {
		return item.ID.String() == totpID
	})
	if !found {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "totp_id is not found")
	}

	if authenticator.Type != (&database.TOTPValidator{}).Type() {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "totp_id is not TOTP")
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	if err := db.Delete(&authenticator).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to delete TOTP", err)
	}

	user.Authenticators = utils.Filter(user.Authenticators, func(item database.UserAuthenticator) bool {
		return item.ID != authenticator.ID
	})

	if !user.HasTwoFactorAuthn() {
		if err := user.DisableTwoFactor(); err != nil {
			return meilingErrors.NewInternalServerError("failed to disable two factor", err)
		}
	}

	return nil
}

func GetUserBackupCodes(caller *tokens.Principal, userID string) (types.GetBackupCodesResponse, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return types.GetBackupCodesResponse{}, err
	}

	remaining := 0
	for _, authenticator := range user.GetAuthenticators((&database.BackupCodeValidator{}).Type()) {
		validator, err := authenticator.GetBackupCodeValidator()
		if err != nil || validator.IsUsed() {
			continue
		}
		remaining++
	}

	return types.GetBackupCodesResponse{Remaining: remaining}, nil
}

func RegenerateUserBackupCodes(req RegenerateUserBackupCodesRequest) (types.RegenerateBackupCodesResponse, error) {
	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return types.RegenerateBackupCodesResponse{}, err
	}
	if !user.HasTwoFactorAuthn() {
		return types.RegenerateBackupCodesResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "there is no two factor authenticator")
	}

	backupCodeConfig := config.BackupCodeConfig{}
	if req.Config != nil {
		backupCodeConfig = req.Config.AuthConfig.BackupCode
	}

	codes, err := database.GenerateBackupCodes(backupCodeConfig.GetCount(), backupCodeConfig.GetCodeBytes())
	if err != nil {
		return types.RegenerateBackupCodesResponse{}, meilingErrors.NewInternalServerError("failed to generate backup codes", err)
	}

	db, err := getDB()
	if err != nil {
		return types.RegenerateBackupCodesResponse{}, err
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ? AND type = ?", user.ID, (&database.BackupCodeValidator{}).Type()).Delete(&database.UserAuthenticator{}).Error; err != nil {
			return err
		}

		for _, code := range codes {
			authenticator, err := user.AddBackupCode(code)
			if err != nil {
				return err
			}

			if err := tx.Create(authenticator).Error; err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return types.RegenerateBackupCodesResponse{}, meilingErrors.NewInternalServerError("failed to regenerate backup codes", err)
	}

	return types.RegenerateBackupCodesResponse{
		Codes:     codes,
		Remaining: len(codes),
	}, nil
}

func DeleteUserBackupCodes(caller *tokens.Principal, userID string) error {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return err
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	if err := db.Where("user_id = ? AND type = ?", user.ID, (&database.BackupCodeValidator{}).Type()).Delete(&database.UserAuthenticator{}).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to delete backup codes", err)
	}

	return nil
}

func GetUserWebAuthn(caller *tokens.Principal, userID string) ([]types.GetWebAuthnResponse, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return nil, err
	}

	authenticators := user.GetAuthenticators((&database.WebAuthnValidator{}).Type())
	return utils.Map(authenticators, func(authenticator database.UserAuthenticator) types.GetWebAuthnResponse {
		return types.GetWebAuthnResponse{
			ID:   authenticator.ID.String(),
			Note: authenticator.Note,
		}
	}), nil
}

func AddUserWebAuthn(req AddUserWebAuthnRequest) (types.AddWebAuthnResponse, error) {
	if req.TokenServices == nil {
		return types.AddWebAuthnResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return types.AddWebAuthnResponse{}, err
	}

	manager := req.TokenServices.RegisterToken()
	if req.Body.Token == "" {
		validator, err := database.NewWebAuthnValidator(user)
		if err != nil {
			return types.AddWebAuthnResponse{}, meilingErrors.NewInternalServerError("failed to create WebAuthn validator", err)
		}

		opts, sess, err := validator.Register()
		if err != nil {
			return types.AddWebAuthnResponse{}, meilingErrors.NewInternalServerError("failed to register WebAuthn", err)
		}

		registerToken, err := manager.New(tokens.ResourceRegisterContent{
			WebAuthnData: &tokens.WebAuthnContent{
				SessionData: *sess,
			},
		})
		if err != nil {
			return types.AddWebAuthnResponse{}, meilingErrors.NewInternalServerError("failed to create register token", err)
		}

		if opts == nil {
			return types.AddWebAuthnResponse{}, meilingErrors.NewInternalServerError("invalid options", nil)
		}

		return types.AddWebAuthnResponse{
			Token:    registerToken,
			Response: &opts.Response,
		}, nil
	}

	payload, err := manager.Get(req.Body.Token)
	if err != nil {
		return types.AddWebAuthnResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid token")
	}

	if payload.WebAuthnData == nil {
		return types.AddWebAuthnResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid token")
	}
	if req.Body.Response == nil {
		return types.AddWebAuthnResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid challenge response")
	}

	validator, err := database.NewWebAuthnValidator(user)
	if err != nil {
		return types.AddWebAuthnResponse{}, meilingErrors.NewInternalServerError("failed to create WebAuthn validator", err)
	}

	raw, err := jsoniter.ConfigFastest.Marshal(req.Body.Response)
	if err != nil {
		return types.AddWebAuthnResponse{}, meilingErrors.NewInternalServerError("failed to marshal response", err)
	}

	response, err := protocol.ParseCredentialCreationResponseBytes(raw)
	if err != nil {
		return types.AddWebAuthnResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "failed to parse response")
	}

	if _, err := validator.ValidateRegister(response, payload.WebAuthnData.SessionData); err != nil {
		return types.AddWebAuthnResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "failed to validate register")
	}

	authn, err := validator.SerializeAuthenticator()
	if err != nil {
		return types.AddWebAuthnResponse{}, meilingErrors.NewInternalServerError("failed to serialize authenticator", err)
	}

	authn.UserID = user.ID
	authn.Note = req.Body.Note

	db, err := getDB()
	if err != nil {
		return types.AddWebAuthnResponse{}, err
	}

	if err := db.Create(&authn).Error; err != nil {
		return types.AddWebAuthnResponse{}, meilingErrors.NewInternalServerError("failed to create authenticator", err)
	}

	return types.AddWebAuthnResponse{}, nil
}

func DeleteUserWebAuthn(caller *tokens.Principal, userID, webAuthnID string) error {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return err
	}

	if webAuthnID == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "webauthn_id is required")
	}

	authenticator, found := utils.Find(user.Authenticators, func(item database.UserAuthenticator) bool {
		return item.ID.String() == webAuthnID
	})
	if !found {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "webauthn_id is not found")
	}

	if authenticator.Type != (&database.WebAuthnValidator{}).Type() {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "webauthn_id is not WebAuthn")
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	if err := db.Delete(&authenticator).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to delete WebAuthn", err)
	}

	user.Authenticators = utils.Filter(user.Authenticators, func(item database.UserAuthenticator) bool {
		return item.ID != authenticator.ID
	})

	if !user.HasTwoFactorAuthn() {
		if err := user.DisableTwoFactor(); err != nil {
			return meilingErrors.NewInternalServerError("failed to disable two factor", err)
		}
	}

	return nil
}

func GetSerializedUserData(caller *tokens.Principal, userID string) (types.SerializedUserData, error) {
	user, err := getAccessibleUser(caller, userID)
	if err != nil {
		return types.SerializedUserData{}, err
	}

	if err := ensureUserDataExists(user); err != nil {
		return types.SerializedUserData{}, err
	}

	return user.UserData.Serialize(), nil
}

func UpdateSerializedUserData(req UpdateUserDataRequest) error {
	user, err := getAccessibleUser(req.Caller, req.UserID)
	if err != nil {
		return err
	}

	if err := ensureUserDataExists(user); err != nil {
		return err
	}

	// A lock refuses a change, not a value sent back as it is.
	if req.Body.Name != nil && *req.Body.Name != user.UserData.Name {
		if !user.UserData.AllowsUpdatingWithBypass("name", req.Caller.IsAdmin()) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "name is locked")
		}
		user.UserData.Name = *req.Body.Name
	}

	if req.Body.DisplayName != nil && *req.Body.DisplayName != user.UserData.DisplayName {
		if !user.UserData.AllowsUpdatingWithBypass("display_name", req.Caller.IsAdmin()) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "displayName is locked")
		}
		user.UserData.DisplayName = *req.Body.DisplayName
	}

	if req.Body.FirstName != nil && *req.Body.FirstName != user.UserData.FirstName {
		if !user.UserData.AllowsUpdatingWithBypass("first_name", req.Caller.IsAdmin()) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "firstName is locked")
		}
		user.UserData.FirstName = *req.Body.FirstName
	}

	if req.Body.LastName != nil && *req.Body.LastName != user.UserData.LastName {
		if !user.UserData.AllowsUpdatingWithBypass("last_name", req.Caller.IsAdmin()) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "lastName is locked")
		}
		user.UserData.LastName = *req.Body.LastName
	}

	if req.Body.MiddleName != nil && !sameValue(req.Body.MiddleName, user.UserData.MiddleName) {
		if !user.UserData.AllowsUpdatingWithBypass("middle_name", req.Caller.IsAdmin()) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "middleName is locked")
		}
		user.UserData.MiddleName = req.Body.MiddleName
	}

	if req.Body.Birthday != nil && (user.UserData.Birthday == nil || !req.Body.Birthday.Equal(*user.UserData.Birthday)) {
		if !user.UserData.AllowsUpdatingWithBypass("birthday", req.Caller.IsAdmin()) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "birthday is locked")
		}
		user.UserData.Birthday = req.Body.Birthday
	}

	nullableUpdates := map[string]any{}
	if req.Body.LanguageSet && !sameValue(req.Body.Language, user.UserData.Language) {
		if !user.UserData.AllowsUpdatingWithBypass("language", req.Caller.IsAdmin()) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "language is locked")
		}
		user.UserData.Language = req.Body.Language
		if req.Body.Language == nil {
			nullableUpdates["language"] = nil
		} else {
			nullableUpdates["language"] = *req.Body.Language
		}
	}

	if req.Body.TimezoneSet && !sameValue(req.Body.Timezone, user.UserData.Timezone) {
		if !user.UserData.AllowsUpdatingWithBypass("timezone", req.Caller.IsAdmin()) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "timezone is locked")
		}
		user.UserData.Timezone = req.Body.Timezone
		if req.Body.Timezone == nil {
			nullableUpdates["timezone"] = nil
		} else {
			nullableUpdates["timezone"] = *req.Body.Timezone
		}
	}

	db, err := getUserDB()
	if err != nil {
		return err
	}

	if err := db.Updates(&user.UserData).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to update user data", err)
	}
	if len(nullableUpdates) > 0 {
		if err := db.Model(&user.UserData).Updates(nullableUpdates).Error; err != nil {
			return meilingErrors.NewInternalServerError("failed to update user data", err)
		}
	}

	return nil
}

// sameValue reports whether an update leaves a nullable field as it is.
func sameValue[T comparable](a, b *T) bool {
	return a == b || (a != nil && b != nil && *a == *b)
}

func GetUserDataLocks(userID string) (map[string]any, error) {
	userData, err := ensurePersistedUserData(userID)
	if err != nil {
		return nil, err
	}
	return userData.UserDataLocks, nil
}

func SetUserDataLocks(userID string, locks map[string]any) error {
	for column, locked := range locks {
		if !slices.Contains(database.UserDataLockableColumns, column) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, column+" is not a lockable field")
		}
		if _, ok := locked.(bool); !ok {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "lock of "+column+" must be a boolean")
		}
	}

	userData, err := ensurePersistedUserData(userID)
	if err != nil {
		return err
	}

	userData.UserDataLocks = locks
	db, err := getDB()
	if err != nil {
		return err
	}

	if err := db.Updates(userData).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to update user data", err)
	}

	return nil
}

func GetUserMetadata(userID string) (map[string]any, error) {
	return metadata.Get(metadata.Users, userID)
}

func UpdateUserMetadata(userID string, data map[string]any) error {
	return metadata.Set(metadata.Users, userID, data)
}

func MergeUserMetadata(userID string, data map[string]any) error {
	return metadata.Merge(metadata.Users, userID, data)
}

func getAccessibleUser(caller *tokens.Principal, userID string) (*database.User, error) {
	if err := ValidateUserSessionAccess(caller, userID); err != nil {
		return nil, err
	}

	return findUserByID(userID)
}

func ensureUserDataExists(user *database.User) error {
	if user == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user is required")
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	if user.UserData.UserID == uuid.Nil {
		user.UserData.UserID = user.ID
	}

	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&user.UserData).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to ensure user data", err)
	}

	if err := db.Where("user_id = ?", user.ID).First(&user.UserData).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to get user data", err)
	}

	return nil
}

func ensurePersistedUserData(userID string) (*database.UserData, error) {
	user, err := findUserByID(userID)
	if err != nil {
		return nil, err
	}

	if err := ensureUserDataExists(user); err != nil {
		return nil, err
	}

	return &user.UserData, nil
}
