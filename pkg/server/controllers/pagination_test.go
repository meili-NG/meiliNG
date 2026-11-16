package controllers

import (
	"testing"

	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
)

func TestHTTPPaginationAppliesUsersDefaultWhenMissing(t *testing.T) {
	t.Parallel()

	got, err := HTTPPagination(0, 0, false, 20)
	if err != nil {
		t.Fatalf("HTTPPagination: %v", err)
	}
	if got == nil {
		t.Fatal("HTTPPagination returned nil pagination")
	}
	if got.Page != 1 || got.Size != 20 {
		t.Fatalf("pagination = %#v, want page=1 size=20", got)
	}
}

func TestHTTPPaginationAppliesOAuth2DefaultWhenMissing(t *testing.T) {
	t.Parallel()

	got, err := HTTPPagination(0, 0, false, 10)
	if err != nil {
		t.Fatalf("HTTPPagination: %v", err)
	}
	if got == nil {
		t.Fatal("HTTPPagination returned nil pagination")
	}
	if got.Page != 1 || got.Size != 10 {
		t.Fatalf("pagination = %#v, want page=1 size=10", got)
	}
}

func TestHTTPPaginationReturnsNilWhenBypassed(t *testing.T) {
	t.Parallel()

	got, err := HTTPPagination(0, 0, true, 20)
	if err != nil {
		t.Fatalf("HTTPPagination: %v", err)
	}
	if got != nil {
		t.Fatalf("pagination = %#v, want nil", got)
	}
}

func TestHTTPPaginationRejectsIncompleteInput(t *testing.T) {
	t.Parallel()

	_, err := HTTPPagination(1, 0, false, 20)
	if err == nil {
		t.Fatal("HTTPPagination error = nil, want invalid request")
	}

	meilingErr, ok := err.(*meilingErrors.Error)
	if !ok {
		t.Fatalf("error type = %T, want *errors.Error", err)
	}
	if meilingErr.Type != meilingErrors.ErrInvalidRequest {
		t.Fatalf("error type = %q, want %q", meilingErr.Type, meilingErrors.ErrInvalidRequest)
	}
}
