package types

import (
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"gorm.io/gorm"
)

type PaginationRequest struct {
	Page int `json:"page"`
	Size int `json:"size"`

	Bypass bool `json:"bypass,omitempty"`
}

type PaginationData struct {
	PaginationRequest
	Total int64 `json:"total"`
}

type PaginatedResponse[T any] struct {
	Data       []T            `json:"data"`
	Pagination PaginationData `json:"pagination"`
}

func GetPaginatedResult[T any](db *gorm.DB, request PaginationRequest, handler func(db *gorm.DB) *gorm.DB, where string, args ...any) PaginatedResponse[T] {
	return getPaginatedResult[T](db, request, handler, where, args...)
}

func getPaginatedResult[T any](db *gorm.DB, request PaginationRequest, handler func(db *gorm.DB) *gorm.DB, where string, args ...any) PaginatedResponse[T] {
	var count int64
	var t T

	query := db.Model(&t)
	query.Where(where, args...).Count(&count)

	var pagination PaginationData = PaginationData{
		PaginationRequest: request,
		Total:             count,
	}

	if count == 0 {
		pagination.Page = 1

		return PaginatedResponse[T]{
			Data:       make([]T, 0),
			Pagination: pagination,
		}
	}

	var data []T
	if !request.Bypass {
		query.Offset((request.Page - 1) * request.Size).Limit(request.Size)
	}
	if handler != nil {
		query = handler(query)
	}
	query.Find(&data)

	return PaginatedResponse[T]{
		Data:       data,
		Pagination: pagination,
	}
}

func serializeResult[T any, U any](result PaginatedResponse[T], serializer func(T) U) PaginatedResponse[U] {
	if result.Data != nil {
		return PaginatedResponse[U]{
			Data:       utils.Map(result.Data, serializer),
			Pagination: result.Pagination,
		}
	}

	return PaginatedResponse[U]{}
}

func GetPaginatedResultSerialized[T any, U any](db *gorm.DB, request PaginationRequest, serializer func(T) U, where string, args ...any) PaginatedResponse[U] {
	result := GetPaginatedResult[T](db, request, nil, where, args...)

	return serializeResult(result, serializer)
}

func GetOrderedPaginatedResultSerialized[T any, U any](db *gorm.DB, request PaginationRequest, serializer func(T) U, orderBy string, where string, args ...any) PaginatedResponse[U] {
	result := GetPaginatedResult[T](db, request, func(db *gorm.DB) *gorm.DB {
		return db.Order(orderBy)
	}, where, args...)

	return serializeResult(result, serializer)
}
