package controllers

import (
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
)

func HTTPPagination(page int, size int, bypass bool, defaultSize int) (*api.PaginationDetail, error) {
	if bypass {
		return nil, nil
	}

	if page == 0 && size == 0 {
		return &api.PaginationDetail{
			Page: 1,
			Size: defaultSize,
		}, nil
	}

	if page <= 0 || size <= 0 {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "page and size must be provided together and be positive")
	}

	return &api.PaginationDetail{
		Page: page,
		Size: size,
	}, nil
}
