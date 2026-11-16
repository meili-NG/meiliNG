package types

import (
	"fmt"
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type paginationTestModel struct {
	ID   int `gorm:"primaryKey"`
	Name string
}

func setupPaginationDB(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}
	if err := db.AutoMigrate(&paginationTestModel{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	if err := db.Create([]paginationTestModel{
		{Name: "alpha"},
		{Name: "beta"},
		{Name: "gamma"},
	}).Error; err != nil {
		t.Fatalf("Create: %v", err)
	}

	return db
}

func TestGetPaginatedResult(t *testing.T) {
	t.Parallel()

	db := setupPaginationDB(t)
	result := GetPaginatedResult[paginationTestModel](db, PaginationRequest{
		Page: 2,
		Size: 2,
	}, func(db *gorm.DB) *gorm.DB {
		return db.Order("id asc")
	}, "1 = 1")

	if result.Pagination.Total != 3 {
		t.Fatalf("total = %d, want 3", result.Pagination.Total)
	}
	if result.Pagination.Page != 2 || result.Pagination.Size != 2 {
		t.Fatalf("pagination = %#v", result.Pagination)
	}
	if len(result.Data) != 1 || result.Data[0].Name != "gamma" {
		t.Fatalf("result.Data = %#v", result.Data)
	}
}

func TestGetPaginatedResultWhenEmpty(t *testing.T) {
	t.Parallel()

	db := setupPaginationDB(t)
	result := GetPaginatedResult[paginationTestModel](db, PaginationRequest{
		Page: 3,
		Size: 2,
	}, nil, "name = ?", "missing")

	if result.Pagination.Total != 0 {
		t.Fatalf("total = %d, want 0", result.Pagination.Total)
	}
	if result.Pagination.Page != 1 {
		t.Fatalf("page = %d, want 1", result.Pagination.Page)
	}
	if len(result.Data) != 0 {
		t.Fatalf("expected empty data, got %#v", result.Data)
	}
}

func TestGetOrderedPaginatedResultSerialized(t *testing.T) {
	t.Parallel()

	db := setupPaginationDB(t)
	result := GetOrderedPaginatedResultSerialized[paginationTestModel, string](db, PaginationRequest{
		Page: 1,
		Size: 2,
	}, func(item paginationTestModel) string {
		return strings.ToUpper(item.Name)
	}, "id desc", "1 = 1")

	if len(result.Data) != 2 {
		t.Fatalf("serialized result length = %d, want 2", len(result.Data))
	}
	if result.Data[0] != "GAMMA" || result.Data[1] != "BETA" {
		t.Fatalf("serialized data = %#v", result.Data)
	}
}

func TestGetPaginatedResultBypassReturnsAllRows(t *testing.T) {
	t.Parallel()

	db := setupPaginationDB(t)
	result := GetPaginatedResult[paginationTestModel](db, PaginationRequest{
		Bypass: true,
	}, func(db *gorm.DB) *gorm.DB {
		return db.Order("id asc")
	}, "1 = 1")

	if result.Pagination.Total != 3 {
		t.Fatalf("total = %d, want 3", result.Pagination.Total)
	}
	if len(result.Data) != 3 {
		t.Fatalf("bypass should return all rows, got %d", len(result.Data))
	}
	if result.Data[0].Name != "alpha" || result.Data[1].Name != "beta" || result.Data[2].Name != "gamma" {
		t.Fatalf("unexpected data: %#v", result.Data)
	}
}

func TestGetPaginatedResultBypassWithWhereClause(t *testing.T) {
	t.Parallel()

	db := setupPaginationDB(t)
	result := GetPaginatedResult[paginationTestModel](db, PaginationRequest{
		Bypass: true,
	}, nil, "name LIKE ?", "%ph%")

	// only "alpha" contains "ph"
	if result.Pagination.Total != 1 {
		t.Fatalf("total = %d, want 1", result.Pagination.Total)
	}
	if len(result.Data) != 1 {
		t.Fatalf("bypass with where clause should return matching rows, got %d", len(result.Data))
	}
	if result.Data[0].Name != "alpha" {
		t.Fatalf("expected alpha, got %q", result.Data[0].Name)
	}
}
