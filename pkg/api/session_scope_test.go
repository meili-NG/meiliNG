package api

import (
	"testing"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// A session user ID is data: one that carries SQL must match no row.
func TestSessionUserIDsAreNotInterpolatedIntoSQL(t *testing.T) {
	db := setupAPITestDB(t)

	owner := database.User{UserFields: models.UserFields{ID: uuid.New()}}
	if err := db.Create(&owner).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	application := database.Application{ApplicationFields: models.ApplicationFields{
		ID:      uuid.New(),
		Name:    "Owned by another user",
		OwnerID: &owner.ID,
	}}
	if err := db.Create(&application).Error; err != nil {
		t.Fatalf("create application: %v", err)
	}

	session := &tokens.SessionPayload{Users: []string{"x') OR ('1'='1"}}

	for _, s := range []*tokens.SessionPayload{session, {}} {
		users, err := ListUsersPaginated(ListUsersRequest{Caller: tokens.SessionPrincipal(s)})
		if err != nil {
			t.Fatalf("ListUsersPaginated: %v", err)
		}
		if len(users.Data) != 0 {
			t.Fatalf("listed %d users for a session that holds none of them", len(users.Data))
		}
	}

	applications, err := ListApplicationsPaginated(&ListApplicationsRequest{Caller: tokens.SessionPrincipal(session), Owned: true})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated: %v", err)
	}
	if len(applications.Data) != 0 {
		t.Fatalf("listed %d applications for a session that owns none of them", len(applications.Data))
	}

	own, err := ListUsersPaginated(ListUsersRequest{Caller: tokens.SessionPrincipal(&tokens.SessionPayload{Users: []string{owner.ID.String()}})})
	if err != nil {
		t.Fatalf("ListUsersPaginated: %v", err)
	}
	if len(own.Data) != 1 || own.Data[0].ID != owner.ID.String() {
		t.Fatalf("a session does not list its own user: %+v", own.Data)
	}
}
