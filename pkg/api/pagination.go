package api

import (
	"github.com/meili-NG/meiliNG/v2/internal/types"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
)

type PaginationDetail struct {
	Page int
	Size int
}

func (p *PaginationDetail) Validate() error {
	if p == nil {
		return nil
	}

	if p.Page <= 0 || p.Size <= 0 {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "pagination.page and pagination.size must be positive")
	}

	return nil
}

func buildPaginationRequest(pagination *PaginationDetail) (types.PaginationRequest, error) {
	if pagination == nil {
		return types.PaginationRequest{Bypass: true}, nil
	}

	if err := pagination.Validate(); err != nil {
		return types.PaginationRequest{}, err
	}

	return types.PaginationRequest{
		Page: pagination.Page,
		Size: pagination.Size,
	}, nil
}
