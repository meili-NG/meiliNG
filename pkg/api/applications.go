package api

import (
	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"gorm.io/gorm"
)

type SelectedApplication struct {
	ID       string
	OwnerID  string
	HasOwner bool
}

func (a SelectedApplication) IsOwnedBy(userID string) bool {
	return a.HasOwner && a.OwnerID == userID
}

func ResolveSelectedApplication(applicationID string) (*SelectedApplication, error) {
	application, err := findApplicationByID(applicationID)
	if err != nil {
		return nil, err
	}

	selected := &SelectedApplication{ID: application.ID.String()}
	if application.OwnerID != nil {
		selected.OwnerID = application.OwnerID.String()
		selected.HasOwner = true
	}

	return selected, nil
}

func ValidateApplicationExists(applicationID string) error {
	_, err := ResolveSelectedApplication(applicationID)
	return err
}

func ValidateApplicationOwnership(caller *tokens.Principal, applicationID string) error {
	application, err := ResolveSelectedApplication(applicationID)
	if err != nil {
		return err
	}
	if caller == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "caller is required")
	}
	if caller.IsAdmin() {
		return nil
	}
	if !application.HasOwner || !caller.HasUser(application.OwnerID) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "you are not owner of this application")
	}
	return nil
}

func ValidateApplicationOwnershipForUser(caller *tokens.Principal, applicationID string, userID string) error {
	if err := ValidateUserSessionAccess(caller, userID); err != nil {
		return err
	}
	application, err := ResolveSelectedApplication(applicationID)
	if err != nil {
		return err
	}
	if caller != nil && caller.IsAdmin() {
		return nil
	}
	if !application.IsOwnedBy(userID) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "you are not owner of this application")
	}
	return nil
}

type CreateApplicationRequest struct {
	Config         *config.MeilingConfig
	Caller         *tokens.Principal
	UserID         string
	Name           string
	IsPublicClient *bool
	RedirectURIs   []string
	Privacy        string
	Terms          string
}

type UpdateApplicationRequest struct {
	Caller         *tokens.Principal
	Name           string
	IsPublicClient *bool
}

type UnauthorizeRequest struct {
	Caller *tokens.Principal
	UserID string
}

type ListApplicationsRequest struct {
	Caller     *tokens.Principal
	Pagination *PaginationDetail
	All        bool
	Owned      bool
	Authorized bool
	UserID     string
}

func ListApplications(req *ListApplicationsRequest) ([]types.SerializedApplication, error) {
	result, err := ListApplicationsPaginated(req)
	if err != nil {
		return nil, err
	}

	return result.Data, nil
}

func ListApplicationsPaginated(req *ListApplicationsRequest) (types.PaginatedSerializedApplication, error) {
	if req.Caller == nil {
		return types.PaginatedSerializedApplication{}, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session required")
	}

	q := "1=1"
	args := []any{}
	all := req.All && req.Caller.IsAdmin()
	authorized := req.Authorized && !all

	if req.UserID != "" && !req.Caller.HasUser(req.UserID) {
		return types.PaginatedSerializedApplication{}, meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "you are not allowed to fetch owned applications of other users")
	}

	if req.Owned {
		if req.UserID == "" {
			q += " AND owner_id IN ?"
			args = append(args, req.Caller.Users())
		} else {
			q += " AND owner_id = ?"
			args = append(args, req.UserID)
		}
	}

	if !all && !req.Owned {
		authorized = true
	}

	if authorized {
		db, err := getDB()
		if err != nil {
			return types.PaginatedSerializedApplication{}, err
		}

		tx := db.Model(&database.ApplicationConsentLog{}).Select("application_id")
		if req.UserID != "" {
			tx = tx.Where("user_id = ?", req.UserID)
		} else {
			tx = tx.Where("user_id IN ?", req.Caller.Users())
		}

		var applicationIDs []string
		if err := tx.Find(&applicationIDs).Error; err != nil {
			return types.PaginatedSerializedApplication{}, meilingErrors.NewInternalServerError("failed to list consent logs", err)
		}

		if len(applicationIDs) == 0 {
			q += " AND 0=1"
		} else {
			q += " AND id IN ?"
			args = append(args, utils.Deduplicate(applicationIDs))
		}
	}

	pagination, err := buildPaginationRequest(req.Pagination)
	if err != nil {
		return types.PaginatedSerializedApplication{}, err
	}

	db, err := getApplicationDB()
	if err != nil {
		return types.PaginatedSerializedApplication{}, err
	}

	return types.GetPaginatedResultSerialized(db, pagination, func(application database.Application) types.SerializedApplication {
		return serializeApplicationForSession(&application, req.Caller, req.Caller.IsAdmin())
	}, q, args...), nil
}

// CreateApplication registers an application together with its OAuth2 client.
func CreateApplication(req *CreateApplicationRequest) (types.SerializedApplication, error) {
	if req.Caller == nil {
		return types.SerializedApplication{}, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session required")
	}

	isAdmin := req.Caller.IsAdmin()
	if !isAdmin && req.UserID == "" {
		return types.SerializedApplication{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user_id is required")
	}
	if !isAdmin && !req.Caller.HasUser(req.UserID) {
		return types.SerializedApplication{}, meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "you are not allowed to create an application for other users")
	}
	if !isAdmin && !req.Config.OAuth2Config.AllowCreate {
		return types.SerializedApplication{}, meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "you are not allowed to create an application")
	}

	var ownerID *uuid.UUID
	if req.UserID != "" {
		id, err := uuid.Parse(req.UserID)
		if err != nil {
			return types.SerializedApplication{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid user_id")
		}
		ownerID = &id
	}

	db, err := getDB()
	if err != nil {
		return types.SerializedApplication{}, err
	}

	// shortcut: count then insert, so concurrent creations can pass the cap by
	// a few; lock the owner's row if the cap must be exact.
	if limit, err := applicationLimit(req.Config, ownerID); err != nil {
		return types.SerializedApplication{}, err
	} else if !isAdmin && limit > 0 {
		var owned int64
		if err := db.Model(&database.Application{}).Where("owner_id = ?", ownerID).Count(&owned).Error; err != nil {
			return types.SerializedApplication{}, meilingErrors.NewInternalServerError("failed to count applications", err)
		}
		if owned >= int64(limit) {
			return types.SerializedApplication{}, meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "you have reached the maximum number of applications")
		}
	}

	id := uuid.New()
	client := &database.OauthClient{
		OAuthClientFields: models.OAuthClientFields{ApplicationID: id},
	}
	application := database.Application{
		ApplicationFields: models.ApplicationFields{
			ID:   id,
			Name: req.Name,
		},
		OauthClient: client,
	}

	if req.IsPublicClient != nil {
		client.IsPublicClient = *req.IsPublicClient
	}

	application.OwnerID = ownerID

	for _, uri := range req.RedirectURIs {
		if !validator.IsValidRedirectURI(uri) {
			return types.SerializedApplication{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid redirect uri")
		}

		client.RedirectURIs = append(client.RedirectURIs, database.OauthRedirectURI{
			OAuthRedirectURIFields: models.OAuthRedirectURIFields{
				ID:       uuid.New(),
				URI:      uri,
				ClientID: id,
			},
		})
	}

	if !validator.IsValidURL(req.Privacy) || !validator.IsValidURL(req.Terms) {
		return types.SerializedApplication{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid privacy or terms")
	}

	application.AddPolicy(database.ApplicationPolicy{
		Terms:   req.Terms,
		Privacy: req.Privacy,
	})

	// A new application starts allowed the default permissions, as its own
	// rows: changing a default later does not touch existing applications.
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&application).Error; err != nil {
			return err
		}
		return tx.Exec("INSERT INTO application_permissions (application_id, permission_id) SELECT ?, id FROM permissions WHERE is_default = ?", id, true).Error
	})
	if err != nil {
		return types.SerializedApplication{}, meilingErrors.NewInternalServerError("failed to create application", err)
	}

	return application.Serialize("-"), nil
}

func GetApplication(applicationID string, caller *tokens.Principal) (types.SerializedApplication, error) {
	application, err := findApplicationByID(applicationID)
	if err != nil {
		return types.SerializedApplication{}, err
	}

	return serializeApplicationForSession(application, caller, false), nil
}

func DeleteApplication(applicationID string) error {
	application, err := findApplicationByID(applicationID)
	if err != nil {
		return err
	}

	if err := application.Delete(); err != nil {
		return meilingErrors.NewInternalServerError("failed to delete application", err)
	}

	return nil
}

func UpdateApplication(applicationID string, req *UpdateApplicationRequest) error {
	if req.Caller == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session required")
	}

	application, err := findApplicationByID(applicationID)
	if err != nil {
		return err
	}

	// Column maps, so false is written instead of skipped as a zero value.
	updates := map[string]any{}
	clientUpdates := map[string]any{}

	if req.Name != "" {
		updates["name"] = req.Name
	}

	if req.IsPublicClient != nil {
		clientUpdates["is_public"] = *req.IsPublicClient
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		if len(updates) > 0 {
			if err := tx.Model(&database.Application{}).Where("id = ?", application.ID).Updates(updates).Error; err != nil {
				return err
			}
		}
		if len(clientUpdates) > 0 {
			return tx.Model(&database.OauthClient{}).Where("application_id = ?", application.ID).Updates(clientUpdates).Error
		}
		return nil
	})
	if err != nil {
		return meilingErrors.NewInternalServerError("failed to update application", err)
	}

	return nil
}

func UnauthorizeApplication(applicationID string, req *UnauthorizeRequest) error {
	if req.Caller == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session required")
	}
	if req.UserID == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user_id is required")
	}

	application, err := findApplicationByID(applicationID)
	if err != nil {
		return err
	}

	if !req.Caller.IsAdmin() {
		isOwnConsent := req.Caller.HasUser(req.UserID)
		isApplicationOwner := application.OwnerID != nil && req.Caller.HasUser(application.OwnerID.String())
		if !isOwnConsent && !isApplicationOwner {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "you are not allowed to revoke this consent")
		}
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	var consentLogs []database.ApplicationConsentLog
	if err := db.Find(&consentLogs, "application_id = ? AND user_id = ?", application.ID, req.UserID).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to find consent logs", err)
	}

	if err := db.Delete(&consentLogs).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to delete consent logs", err)
	}

	return nil
}

func serializeApplicationForSession(application *database.Application, caller *tokens.Principal, full bool) types.SerializedApplication {
	if full {
		return application.Serialize("-")
	}

	flags := []string{"user"}
	if caller != nil {
		isOwner := application.OwnerID != nil && caller.HasUser(application.OwnerID.String())
		if caller.IsAdmin() || isOwner {
			flags = append(flags, "owner")
		}
	}

	return application.Serialize(flags...)
}

// GetApplicationPermissionLimit reports whether the application is limited in
// what it may request, and the permissions an admin allowed it.
func GetApplicationPermissionLimit(applicationID string) (types.ApplicationPermissionLimitSerialized, error) {
	application, err := findApplicationByID(applicationID)
	if err != nil {
		return types.ApplicationPermissionLimitSerialized{}, err
	}

	allowed, err := application.AllowedPermissions()
	if err != nil {
		return types.ApplicationPermissionLimitSerialized{}, meilingErrors.NewInternalServerError("failed to list application permissions", err)
	}

	permissions := make([]types.PermissionSerialized, 0, len(allowed))
	for _, permission := range allowed {
		permissions = append(permissions, permission.Serialize())
	}

	return types.ApplicationPermissionLimitSerialized{Limited: !application.AllowAnyPermission, Permissions: permissions}, nil
}

// SetApplicationPermissionLimit replaces the application's limit flag and
// allowed permissions as a whole. An unknown permission id changes nothing.
func SetApplicationPermissionLimit(applicationID string, limited bool, permissionIDs []string) (types.ApplicationPermissionLimitSerialized, error) {
	application, err := findApplicationByID(applicationID)
	if err != nil {
		return types.ApplicationPermissionLimitSerialized{}, err
	}

	ids := make([]uuid.UUID, 0, len(permissionIDs))
	for _, permissionID := range permissionIDs {
		id, err := uuid.Parse(permissionID)
		if err != nil {
			return types.ApplicationPermissionLimitSerialized{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "permissionIds contains an invalid id: "+permissionID)
		}
		ids = append(ids, id)
	}

	// Locked, so a permission cannot be deleted between the existence check and the insert.
	err = withLockedPermissionTree(func(tx *gorm.DB, tree *database.PermissionTree) error {
		allowed := make([]database.ApplicationPermission, 0, len(ids))
		for _, id := range utils.Deduplicate(ids) {
			if !tree.Has(id) {
				return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "permission not found: "+id.String())
			}
			allowed = append(allowed, database.ApplicationPermission{
				ApplicationPermissionFields: models.ApplicationPermissionFields{
					ApplicationID: application.ID,
					PermissionID:  id,
				},
			})
		}

		if err := tx.Model(&database.Application{}).Where("id = ?", application.ID).Update("allow_any_permission", !limited).Error; err != nil {
			return err
		}
		if err := tx.Where("application_id = ?", application.ID).Delete(&database.ApplicationPermission{}).Error; err != nil {
			return err
		}
		if len(allowed) == 0 {
			return nil
		}
		return tx.Create(&allowed).Error
	})
	if err != nil {
		return types.ApplicationPermissionLimitSerialized{}, err
	}

	return GetApplicationPermissionLimit(applicationID)
}

// applicationLimit is how many applications owner may own: the cap an admin
// set for that user, else oauth2.maxApplications. 0 means no cap.
func applicationLimit(cfg *config.MeilingConfig, owner *uuid.UUID) (int, error) {
	if owner == nil {
		return 0, nil
	}
	user, err := findUserByID(owner.String())
	if err != nil {
		return 0, err
	}
	if user.MaxApplications != nil {
		return *user.MaxApplications, nil
	}
	return cfg.OAuth2Config.MaxApplications, nil
}
