package api

import (
	"testing"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"gorm.io/gorm"
)

// seedUpdateTestApplication creates an application whose OAuth2 client carries
// the given flags and returns its ID.
func seedUpdateTestApplication(t *testing.T, db *gorm.DB, client models.OAuthClientFields) uuid.UUID {
	t.Helper()

	application := database.Application{
		ApplicationFields: models.ApplicationFields{ID: uuid.New(), Name: "Update Test Application"},
		OauthClient:       &database.OauthClient{OAuthClientFields: client},
	}
	if err := db.Create(&application).Error; err != nil {
		t.Fatalf("Create application: %v", err)
	}
	return application.ID
}

func reloadApplication(t *testing.T, applicationID uuid.UUID) *database.Application {
	t.Helper()

	application, err := findApplicationByID(applicationID.String())
	if err != nil {
		t.Fatalf("findApplicationByID: %v", err)
	}
	if application.OauthClient == nil {
		t.Fatal("application has no OAuth2 client")
	}
	return application
}

func boolPtr(b bool) *bool { return &b }

// TestUpdateApplicationPublicToConfidential proves switching IsPublicClient
// from true to false persists; a struct-based Updates would skip the zero
// value.
func TestUpdateApplicationPublicToConfidential(t *testing.T) {
	db := setupAPITestDB(t)
	applicationID := seedUpdateTestApplication(t, db, models.OAuthClientFields{IsPublicClient: true})

	err := UpdateApplication(applicationID.String(), &UpdateApplicationRequest{
		Caller:         &tokens.Principal{Kind: tokens.PrincipalAdminToken},
		IsPublicClient: boolPtr(false),
	})
	if err != nil {
		t.Fatalf("UpdateApplication: %v", err)
	}

	if got := reloadApplication(t, applicationID); got.OauthClient.IsPublicClient != false {
		t.Fatalf("IsPublicClient = %v, want false (false was not written)", got.OauthClient.IsPublicClient)
	}
}

// TestUpdateApplicationConfidentialToPublic covers the other direction
// (false to true).
func TestUpdateApplicationConfidentialToPublic(t *testing.T) {
	db := setupAPITestDB(t)
	applicationID := seedUpdateTestApplication(t, db, models.OAuthClientFields{})

	err := UpdateApplication(applicationID.String(), &UpdateApplicationRequest{
		Caller:         &tokens.Principal{Kind: tokens.PrincipalAdminToken},
		IsPublicClient: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("UpdateApplication: %v", err)
	}

	if got := reloadApplication(t, applicationID); got.OauthClient.IsPublicClient != true {
		t.Fatalf("IsPublicClient = %v, want true", got.OauthClient.IsPublicClient)
	}
}

// TestUpdateApplicationNameOnlyPreservesPublicFlag ensures a partial update
// (only Name set) does not disturb the existing IsPublicClient value. The
// column-map approach only writes the fields explicitly provided.
func TestUpdateApplicationNameOnlyPreservesPublicFlag(t *testing.T) {
	db := setupAPITestDB(t)
	applicationID := seedUpdateTestApplication(t, db, models.OAuthClientFields{IsPublicClient: true})

	err := UpdateApplication(applicationID.String(), &UpdateApplicationRequest{
		Caller: &tokens.Principal{Kind: tokens.PrincipalAdminToken},
		Name:   "Renamed Application",
	})
	if err != nil {
		t.Fatalf("UpdateApplication: %v", err)
	}

	got := reloadApplication(t, applicationID)
	if got.Name != "Renamed Application" {
		t.Fatalf("Name = %q, want %q", got.Name, "Renamed Application")
	}
	if got.OauthClient.IsPublicClient != true {
		t.Fatalf("IsPublicClient = %v, want true (unset field must be preserved)", got.OauthClient.IsPublicClient)
	}
}
