package v2

import (
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// Huma Input/Output types

type ListUsersInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.PageSizePaginationInput
	All    bool   `query:"all" doc:"Fetch all if you are admin" required:"false"`
	Bypass bool   `query:"bypass" doc:"Bypass pagination and fetch everything at once" required:"false"`
	Search string `query:"search" doc:"Search query" required:"false"`
}

type ListUsersOutput struct {
	Body types.PaginatedUserSerialized
}

type CreateUserInput struct {
	controllers.SessionAuthorizationHeaderInput
	Body types.CreateUserRequest
}

type CreateUserOutput struct {
	Location string `header:"Location" doc:"Location of the created user"`
}

type BulkCheckUsersInput struct {
	controllers.SessionAuthorizationHeaderInput
	Body types.BulkCheckUsersRequest
}

type BulkCheckUsersOutput struct {
	Body types.BulkCheckUsersResponse
}
