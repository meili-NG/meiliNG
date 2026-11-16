package api

import (
	"errors"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"gorm.io/gorm"
)

// maxAudienceLength bounds a registered audience; it is an identifier, usually
// a URL, never free text.
const maxAudienceLength = 512

// maxAudienceDescriptionLength bounds the operator-facing note on an audience.
const maxAudienceDescriptionLength = 1024

// validateAudienceName rejects audiences that could not be requested as one
// value: the token endpoint splits the audience parameter on spaces.
func validateAudienceName(audience string) error {
	if audience == "" || len(audience) > maxAudienceLength {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid audience")
	}
	if strings.IndexFunc(audience, unicode.IsSpace) >= 0 {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "audience must not contain whitespace")
	}
	return nil
}

func validateAudienceDescription(description string) error {
	if len(description) > maxAudienceDescriptionLength {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "description is too long")
	}
	return nil
}

func serializeAudience(audience database.OauthAudience, clientCount int64) types.AudienceSerialized {
	return types.AudienceSerialized{
		ID:          audience.ID.String(),
		Audience:    audience.Audience,
		Description: audience.Description,
		ClientCount: clientCount,
	}
}

func findOAuth2AudienceByID(audienceID string) (*database.OauthAudience, error) {
	if audienceID == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "audienceId is required")
	}
	if _, err := uuid.Parse(audienceID); err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "audience is not found")
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}

	var audience database.OauthAudience
	if err := db.First(&audience, "id = ?", audienceID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "audience is not found")
		}
		return nil, meilingErrors.NewInternalServerError("failed to find audience", err)
	}

	return &audience, nil
}

// ListOAuth2Audiences returns every audience registered on this instance, with
// how many clients each one is assigned to.
func ListOAuth2Audiences() ([]types.AudienceSerialized, error) {
	db, err := getDB()
	if err != nil {
		return nil, err
	}

	var audiences []database.OauthAudience
	if err := db.Order("audience asc").Find(&audiences).Error; err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to list audiences", err)
	}

	counts, err := countAudienceAssignments(db)
	if err != nil {
		return nil, err
	}

	return utils.Map(audiences, func(audience database.OauthAudience) types.AudienceSerialized {
		return serializeAudience(audience, counts[audience.ID])
	}), nil
}

func countAudienceAssignments(db *gorm.DB) (map[uuid.UUID]int64, error) {
	var rows []struct {
		AudienceID uuid.UUID
		Total      int64
	}
	if err := db.Model(&database.OauthClientAudience{}).
		Select("audience_id", "COUNT(*) as total").
		Group("audience_id").
		Find(&rows).Error; err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to count audience assignments", err)
	}

	counts := make(map[uuid.UUID]int64, len(rows))
	for _, row := range rows {
		counts[row.AudienceID] = row.Total
	}
	return counts, nil
}

func GetOAuth2Audience(audienceID string) (types.AudienceSerialized, error) {
	audience, err := findOAuth2AudienceByID(audienceID)
	if err != nil {
		return types.AudienceSerialized{}, err
	}

	db, err := getDB()
	if err != nil {
		return types.AudienceSerialized{}, err
	}

	var clientCount int64
	if err := db.Model(&database.OauthClientAudience{}).
		Where("audience_id = ?", audience.ID).
		Count(&clientCount).Error; err != nil {
		return types.AudienceSerialized{}, meilingErrors.NewInternalServerError("failed to count audience assignments", err)
	}

	return serializeAudience(*audience, clientCount), nil
}

func CreateOAuth2Audience(audience string, description string) (types.AudienceSerialized, error) {
	audience = strings.TrimSpace(audience)
	description = strings.TrimSpace(description)
	if err := validateAudienceName(audience); err != nil {
		return types.AudienceSerialized{}, err
	}
	if err := validateAudienceDescription(description); err != nil {
		return types.AudienceSerialized{}, err
	}

	db, err := getDB()
	if err != nil {
		return types.AudienceSerialized{}, err
	}

	var existing database.OauthAudience
	err = db.First(&existing, "audience = ?", audience).Error
	if err == nil {
		return types.AudienceSerialized{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "audience is already registered")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return types.AudienceSerialized{}, meilingErrors.NewInternalServerError("failed to check audience", err)
	}

	record := database.OauthAudience{
		OAuthAudienceFields: models.OAuthAudienceFields{
			ID:          uuid.New(),
			Audience:    audience,
			Description: description,
		},
	}
	if err := db.Create(&record).Error; err != nil {
		return types.AudienceSerialized{}, meilingErrors.NewInternalServerError("failed to create audience", err)
	}

	return serializeAudience(record, 0), nil
}

func UpdateOAuth2Audience(audienceID string, description *string) (types.AudienceSerialized, error) {
	audience, err := findOAuth2AudienceByID(audienceID)
	if err != nil {
		return types.AudienceSerialized{}, err
	}

	if description != nil {
		trimmed := strings.TrimSpace(*description)
		if err := validateAudienceDescription(trimmed); err != nil {
			return types.AudienceSerialized{}, err
		}

		db, err := getDB()
		if err != nil {
			return types.AudienceSerialized{}, err
		}
		if err := db.Model(&database.OauthAudience{}).
			Where("id = ?", audience.ID).
			Update("description", trimmed).Error; err != nil {
			return types.AudienceSerialized{}, meilingErrors.NewInternalServerError("failed to update audience", err)
		}
		audience.Description = trimmed
	}

	return GetOAuth2Audience(audience.ID.String())
}

// DeleteOAuth2Audience removes an audience from the catalog. It refuses while
// clients are still assigned to it, so revoking a resource server is a
// deliberate two-step: unassign the clients, then delete.
func DeleteOAuth2Audience(audienceID string) error {
	audience, err := findOAuth2AudienceByID(audienceID)
	if err != nil {
		return err
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	var clientCount int64
	if err := db.Model(&database.OauthClientAudience{}).
		Where("audience_id = ?", audience.ID).
		Count(&clientCount).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to count audience assignments", err)
	}
	if clientCount > 0 {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "audience is still assigned to clients")
	}

	if err := db.Delete(&database.OauthAudience{}, "id = ?", audience.ID).Error; err != nil {
		return meilingErrors.NewInternalServerError("failed to delete audience", err)
	}

	return nil
}

// ListOAuth2AudienceClients returns the clients an audience is assigned to, so
// an admin can see the blast radius before deleting it.
func ListOAuth2AudienceClients(audienceID string) ([]types.AudienceClientSerialized, error) {
	audience, err := findOAuth2AudienceByID(audienceID)
	if err != nil {
		return nil, err
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}

	var assignments []database.OauthClientAudience
	if err := db.Find(&assignments, "audience_id = ?", audience.ID).Error; err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to list audience clients", err)
	}

	clientIDs := utils.Map(assignments, func(assignment database.OauthClientAudience) uuid.UUID {
		return assignment.ClientID
	})

	var applications []database.Application
	if len(clientIDs) > 0 {
		if err := db.Find(&applications, "id IN ?", clientIDs).Error; err != nil {
			return nil, meilingErrors.NewInternalServerError("failed to list audience clients", err)
		}
	}

	names := make(map[uuid.UUID]string, len(applications))
	for _, application := range applications {
		names[application.ID] = application.Name
	}

	return utils.Map(assignments, func(assignment database.OauthClientAudience) types.AudienceClientSerialized {
		return types.AudienceClientSerialized{
			ID:         assignment.ID.String(),
			ClientID:   assignment.ClientID.String(),
			ClientName: names[assignment.ClientID],
		}
	}), nil
}
