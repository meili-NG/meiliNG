package api

import (
	"fmt"
	"testing"

	"github.com/meili-NG/meiliNG/v2/internal/database"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAPITestDB(t *testing.T) *gorm.DB {
	t.Helper()

	database.ResetInstance()
	SetDatabaseConfig(&DatabaseConfig{
		Type: "sqlite",
		DSN:  fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()),
	})
	SetDependencies(&Dependencies{
		GeneralizePhone: func(phone string) (string, error) {
			return phone, nil
		},
		IsValidOAuth2URI: func(uri string) bool {
			return true
		},
		GetDialector: func(cfg *DatabaseConfig) gorm.Dialector {
			return sqlite.Open(cfg.DSN)
		},
	})

	if err := InitializeDatabase(); err != nil {
		t.Fatalf("InitializeDatabase: %v", err)
	}

	db, err := database.GetDatabase()
	if err != nil {
		t.Fatalf("GetDatabase: %v", err)
	}

	return db
}

func assertMeilingErrorType(t *testing.T, err error, want meilingErrors.ErrorType) {
	t.Helper()

	meilingErr, ok := err.(*meilingErrors.Error)
	if !ok {
		t.Fatalf("error type = %T, want *errors.Error", err)
	}
	if meilingErr.Type != want {
		t.Fatalf("error type = %q, want %q", meilingErr.Type, want)
	}
}

func TestBuildPaginationRequestTreatsNilAsBypass(t *testing.T) {
	got, err := buildPaginationRequest(nil)
	if err != nil {
		t.Fatalf("buildPaginationRequest(nil): %v", err)
	}
	if !got.Bypass {
		t.Fatalf("Bypass = %v, want true", got.Bypass)
	}
}

func TestBuildPaginationRequestRejectsIncompletePagination(t *testing.T) {
	_, err := buildPaginationRequest(&PaginationDetail{Page: 1})
	if err == nil {
		t.Fatal("buildPaginationRequest error = nil, want invalid request")
	}

	assertMeilingErrorType(t, err, meilingErrors.ErrInvalidRequest)
}

func TestBuildPaginationRequestRejectsNonPositivePagination(t *testing.T) {
	_, err := buildPaginationRequest(&PaginationDetail{Page: -1, Size: 10})
	if err == nil {
		t.Fatal("buildPaginationRequest error = nil, want invalid request")
	}

	assertMeilingErrorType(t, err, meilingErrors.ErrInvalidRequest)
}

func TestListUsersPaginatedNilPaginationFetchesAll(t *testing.T) {
	db := setupAPITestDB(t)
	for i := 0; i < 3; i++ {
		user, err := database.NewUser()
		if err != nil {
			t.Fatalf("NewUser: %v", err)
		}
		if err := db.Create(user).Error; err != nil {
			t.Fatalf("Create user: %v", err)
		}
	}

	result, err := ListUsersPaginated(ListUsersRequest{
		Caller: &tokens.Principal{Kind: tokens.PrincipalAdminToken},
		All:    true,
	})
	if err != nil {
		t.Fatalf("ListUsersPaginated: %v", err)
	}

	if len(result.Data) != 3 {
		t.Fatalf("len(result.Data) = %d, want 3", len(result.Data))
	}
	if !result.Pagination.Bypass {
		t.Fatalf("Pagination.Bypass = %v, want true", result.Pagination.Bypass)
	}
}

func TestListUsersPaginatedRejectsIncompletePagination(t *testing.T) {
	_, err := ListUsersPaginated(ListUsersRequest{
		Caller:     &tokens.Principal{Kind: tokens.PrincipalAdminToken},
		Pagination: &PaginationDetail{Page: 1},
	})
	if err == nil {
		t.Fatal("ListUsersPaginated error = nil, want invalid request")
	}

	assertMeilingErrorType(t, err, meilingErrors.ErrInvalidRequest)
}

func TestListApplicationsPaginatedNilPaginationFetchesAll(t *testing.T) {
	db := setupAPITestDB(t)
	for i := 0; i < 3; i++ {
		application := database.Application{}
		if err := db.Create(&application).Error; err != nil {
			t.Fatalf("Create application: %v", err)
		}
	}

	result, err := ListApplicationsPaginated(&ListApplicationsRequest{
		Caller: &tokens.Principal{Kind: tokens.PrincipalAdminToken},
		All:    true,
	})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated: %v", err)
	}

	if len(result.Data) != 3 {
		t.Fatalf("len(result.Data) = %d, want 3", len(result.Data))
	}
	if !result.Pagination.Bypass {
		t.Fatalf("Pagination.Bypass = %v, want true", result.Pagination.Bypass)
	}
}

func TestListApplicationsPaginatedRejectsIncompletePagination(t *testing.T) {
	_, err := ListApplicationsPaginated(&ListApplicationsRequest{
		Caller:     &tokens.Principal{Kind: tokens.PrincipalAdminToken},
		Pagination: &PaginationDetail{Page: 1},
		All:        true,
	})
	if err == nil {
		t.Fatal("ListApplicationsPaginated error = nil, want invalid request")
	}

	assertMeilingErrorType(t, err, meilingErrors.ErrInvalidRequest)
}
