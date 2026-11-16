// Package metadata keeps free-form data on core records for plugins and
// distributions: a provider or a wrapper stores what it needs on a user, an
// application, a permission or an audience, and reads it back, without a
// schema of its own. Core never reads metadata.
//
//	app, _ := metadata.Get(metadata.Applications, appID)
//	if app["tier"] == "internal" { ... }
//
// Over HTTP, admins read and change it at <record>/metadata.
package metadata

import (
	"errors"

	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Kind is a kind of record that carries metadata.
type Kind string

const (
	Users        Kind = "users"
	Applications Kind = "applications"
	Permissions  Kind = "permissions"
	Audiences    Kind = "audiences"
)

// holder is a record loaded for its metadata.
type holder struct {
	record any
	field  *map[string]any
	column string
}

// load finds the record of kind with id. A user without profile data yet gets
// an empty row, so metadata can be stored for any existing user.
func load(db *gorm.DB, kind Kind, id string) (holder, error) {
	var h holder
	var err error
	switch kind {
	case Applications:
		var r database.Application
		err = db.Where("id = ?", id).First(&r).Error
		h = holder{&r, &r.Metadata, "metadata"}
	case Permissions:
		var r database.Permission
		err = db.Where("id = ?", id).First(&r).Error
		h = holder{&r, &r.Metadata, "metadata"}
	case Audiences:
		var r database.OauthAudience
		err = db.Where("id = ?", id).First(&r).Error
		h = holder{&r, &r.Metadata, "metadata"}
	case Users:
		var user database.User
		if err = db.Select("id").Where("id = ? AND deleted_at IS NULL", id).First(&user).Error; err == nil {
			r := database.UserData{}
			r.UserID = user.ID
			if err = db.Clauses(clause.OnConflict{DoNothing: true}).Create(&r).Error; err == nil {
				err = db.Where("user_id = ?", user.ID).First(&r).Error
			}
			h = holder{&r, &r.Metadata, "data"}
		}
	default:
		return h, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "unknown metadata kind")
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return h, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, string(kind)+" record not found")
	}
	if err != nil {
		return h, meilingErrors.NewInternalServerError("failed to load metadata", err)
	}
	if *h.field == nil {
		*h.field = map[string]any{}
	}
	return h, nil
}

// Get returns the metadata of the record of kind with id; empty when none was stored.
func Get(kind Kind, id string) (map[string]any, error) {
	db, err := database.GetDatabase()
	if err != nil {
		return nil, err
	}
	h, err := load(db, kind, id)
	if err != nil {
		return nil, err
	}
	return *h.field, nil
}

// Set replaces the metadata of the record of kind with id.
func Set(kind Kind, id string, data map[string]any) error {
	return update(kind, id, func(map[string]any) map[string]any { return data })
}

// Merge merges data into the metadata of the record of kind with id, as a
// JSON merge: objects merge key by key, anything else replaces.
func Merge(kind Kind, id string, data map[string]any) error {
	return update(kind, id, func(current map[string]any) map[string]any { return utils.MergeJSON(current, data) })
}

func update(kind Kind, id string, change func(map[string]any) map[string]any) error {
	db, err := database.GetDatabase()
	if err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		h, err := load(tx, kind, id)
		if err != nil {
			return err
		}
		*h.field = change(*h.field)
		if *h.field == nil {
			*h.field = map[string]any{}
		}
		if err := tx.Model(h.record).Select(h.column).Updates(h.record).Error; err != nil {
			return meilingErrors.NewInternalServerError("failed to save metadata", err)
		}
		return nil
	})
}
