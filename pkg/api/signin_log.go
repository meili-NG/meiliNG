package api

import (
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/geoip"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// SignInLogData contains data for creating a sign-in log entry
type SignInLogData struct {
	IP          string
	Country     string
	CountryCode string
	GeoIPData   map[string]any
	UserAgent   string
}

// MarkSignIn records sign-in events for the given users
func MarkSignIn(sess *tokens.SessionPayload, data *SignInLogData, userIds ...uuid.UUID) error {
	if sess == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "session required")
	}

	sessionID, err := uuid.Parse(sess.SID)
	if err != nil {
		return meilingErrors.NewInternalServerError("invalid session id", err)
	}

	metadata := SignInLogData{}
	if data != nil {
		metadata = *data
	}

	if (metadata.Country == "" || len(metadata.GeoIPData) == 0) && metadata.IP != "" {
		if deps := database.GetDependencies(); deps != nil && deps.ResolveGeoIP != nil {
			result, resolveErr := deps.ResolveGeoIP(metadata.IP)
			if resolveErr == nil && result != nil {
				if metadata.CountryCode == "" {
					metadata.CountryCode = result.CountryCode
				}
				if metadata.Country == "" {
					metadata.Country = result.Country
				}
				if len(metadata.GeoIPData) == 0 {
					metadata.GeoIPData = result.Data
				}
			}
		}
	}

	countryCode := geoip.NormalizeCountryCode(metadata.CountryCode)
	if countryCode == "" {
		countryCode = geoip.NormalizeCountryCode(metadata.Country)
	}
	if countryCode == "" {
		countryCode = geoip.CountryCodeFromData(metadata.GeoIPData)
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	for _, userId := range userIds {
		log := &database.SignInLog{
			SignInLogFields: models.SignInLogFields{
				SessionID:  sessionID,
				UserID:     userId,
				SignedInAt: time.Now(),
				ExpiresAt:  sessionExpiresAt(sess),
				IP:         metadata.IP,
				Country:    countryCode,
				GeoIPData:  metadata.GeoIPData,
				UserAgent:  metadata.UserAgent,
			},
		}
		err = db.Create(log).Error
		if err != nil {
			return meilingErrors.NewInternalServerError("failed to create sign-in log", err)
		}
	}

	return nil
}

func UpdateSignInLogExpiry(sess *tokens.SessionPayload) error {
	if sess == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "session required")
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	if err := db.Model(&database.SignInLog{}).
		Where("session_id = ? AND signed_out_at IS NULL", uuid.MustParse(sess.SID)).
		Update("expires_at", sessionExpiresAt(sess)).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to update sign-in log expiry", err)
	}

	return nil
}

func sessionExpiresAt(sess *tokens.SessionPayload) *time.Time {
	if sess == nil || sess.ExpiresAt.IsZero() {
		return nil
	}

	expiresAt := sess.ExpiresAt
	return &expiresAt
}

// MarkSignOut records sign-out events for the given users
func MarkSignOut(sess *tokens.SessionPayload, userIds ...uuid.UUID) error {
	db, err := getDB()
	if err != nil {
		return err
	}

	now := time.Now()
	for _, userId := range userIds {
		var logs []database.SignInLog
		err = db.Find(&logs, "session_id = ? AND user_id = ? AND signed_out_at IS NULL", uuid.MustParse(sess.SID), userId).Error

		if err != nil {
			return meilingErrors.NewInternalServerError("failed to find sign-in logs", err)
		}

		for _, log := range logs {
			log.SignedOutAt = &now
			err = db.Updates(&log).Error
			if err != nil {
				return meilingErrors.NewInternalServerError("failed to update sign-in log", err)
			}
		}
	}

	return nil
}
