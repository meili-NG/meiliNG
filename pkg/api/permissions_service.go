package api

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"gorm.io/gorm"
)

type ListPermissionsRequest struct {
	Caller     *tokens.Principal
	Pagination *PaginationDetail
	All        bool
	Scope      string
}

func permissionListQuery(req *ListPermissionsRequest) (string, []any, error) {
	if req == nil || req.Caller == nil {
		return "", nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session required")
	}

	query := "is_public = TRUE"
	if req.Caller.IsAdmin() && req.All {
		query = ""
	}

	args := make([]any, 0)
	if req.Scope != "" {
		query = "scope IN ?"
		args = append(args, strings.Split(req.Scope, " "))
	}

	return query, args, nil
}

func ListPermissions(req *ListPermissionsRequest) ([]types.PermissionSerialized, error) {
	query, args, err := permissionListQuery(req)
	if err != nil {
		return nil, err
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}

	var permissions []database.Permission
	tx := db
	if query != "" {
		tx = tx.Where(query, args...)
	}
	if err := tx.Find(&permissions).Error; err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to list permissions", err)
	}

	return utils.Map(permissions, func(permission database.Permission) types.PermissionSerialized {
		return permission.Serialize()
	}), nil
}

func ListPermissionsPaginated(req *ListPermissionsRequest) (types.PaginatedPermissionSerialized, error) {
	query, args, err := permissionListQuery(req)
	if err != nil {
		return types.PaginatedPermissionSerialized{}, err
	}

	pagination, err := buildPaginationRequest(req.Pagination)
	if err != nil {
		return types.PaginatedPermissionSerialized{}, err
	}

	db, err := getDB()
	if err != nil {
		return types.PaginatedPermissionSerialized{}, err
	}

	// Ordered so a client walking the pages never skips a row.
	return types.GetOrderedPaginatedResultSerialized(db, pagination, func(permission database.Permission) types.PermissionSerialized {
		return permission.Serialize()
	}, "scope ASC", query, args...), nil
}

type CreatePermissionRequest struct {
	Scope     string
	IsPublic  bool
	IsDefault bool
	ParentID  string
	Message   string
}

func parsePermissionParentID(parentID string) (uuid.NullUUID, error) {
	if parentID == "" {
		return uuid.NullUUID{}, nil
	}

	id, err := uuid.Parse(parentID)
	if err != nil {
		return uuid.NullUUID{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "parentId is invalid")
	}
	return uuid.NullUUID{UUID: id, Valid: true}, nil
}

// withLockedPermissionTree keeps the tree check and the write that depends on it in one transaction.
func withLockedPermissionTree(fn func(tx *gorm.DB, tree *database.PermissionTree) error) error {
	err := database.WithLockedPermissionTree(fn)

	var meilingErr *meilingErrors.Error
	if err != nil && !errors.As(err, &meilingErr) {
		return meilingErrors.NewInternalServerError("failed to update permissions", err)
	}
	return err
}

func CreatePermission(req *CreatePermissionRequest) error {
	if req == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "request is required")
	}

	parentID, err := parsePermissionParentID(req.ParentID)
	if err != nil {
		return err
	}

	return withLockedPermissionTree(func(tx *gorm.DB, tree *database.PermissionTree) error {
		if parentID.Valid && !tree.Has(parentID.UUID) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "parent permission not found")
		}

		permission := database.Permission{
			PermissionFields: models.PermissionFields{
				Scope:     req.Scope,
				IsPublic:  req.IsPublic,
				IsDefault: req.IsDefault,
				ParentID:  parentID,
				Message:   req.Message,
			},
		}

		if err := tx.Create(&permission).Error; err != nil {
			return meilingErrors.NewInternalServerError("failed to create permission", err)
		}

		return nil
	})
}

type UpdatePermissionRequest struct {
	ID        string
	ParentID  string
	IsPublic  bool
	IsDefault bool
	Message   string
}

// UpdatePermission replaces the mutable fields of a permission; scope is immutable.
func UpdatePermission(req *UpdatePermissionRequest) error {
	if req == nil || req.ID == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "id is required")
	}

	id, err := uuid.Parse(req.ID)
	if err != nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "id is invalid")
	}
	parentID, err := parsePermissionParentID(req.ParentID)
	if err != nil {
		return err
	}

	return withLockedPermissionTree(func(tx *gorm.DB, tree *database.PermissionTree) error {
		if !tree.Has(id) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "permission not found")
		}
		if parentID.Valid {
			if !tree.Has(parentID.UUID) {
				return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "parent permission not found")
			}
			if tree.WouldCycle(id, parentID.UUID) {
				return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "a permission cannot be placed under itself or one of its child permissions")
			}
		}

		// A map, so false and NULL are written instead of skipped as zero values.
		if err := tx.Model(&database.Permission{}).Where("id = ?", id).Updates(map[string]any{
			"parent_id":  parentID,
			"is_public":  req.IsPublic,
			"is_default": req.IsDefault,
			"message":    req.Message,
		}).Error; err != nil {
			return meilingErrors.NewInternalServerError("failed to update permission", err)
		}

		return nil
	})
}

func DeletePermission(permissionID string) error {
	if permissionID == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "id is required")
	}

	return withLockedPermissionTree(func(tx *gorm.DB, tree *database.PermissionTree) error {
		var permission database.Permission
		if err := tx.First(&permission, "id = ?", permissionID).Error; err != nil {
			return meilingErrors.NewInternalServerError("failed to find permission", err)
		}
		if permission.ID == uuid.Nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "permission not found")
		}
		if len(tree.Descendants(permission.ID)) > 0 {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "permission has child permissions; delete or move them first")
		}

		if err := tx.Where("permission_id = ?", permission.ID).Delete(&database.ApplicationPermission{}).Error; err != nil {
			return meilingErrors.NewInternalServerError("failed to remove permission from application limits", err)
		}
		if err := tx.Delete(&permission).Error; err != nil {
			return meilingErrors.NewInternalServerError("failed to delete permission", err)
		}

		return nil
	})
}
