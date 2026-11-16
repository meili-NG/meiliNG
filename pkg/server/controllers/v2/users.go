package v2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// UserController handles user-related business logic
type UserController struct {
	controllers.Base
}

// NewUserController creates a new user controller
func NewUserController(a *app.Meiling) *UserController {
	return &UserController{Base: controllers.NewBase(a)}
}

func (c *UserController) HandleListUsers(ctx context.Context, input *ListUsersInput) (*ListUsersOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	pagination, err := controllers.HTTPPagination(input.Page, input.Size, input.Bypass, 20)
	if err != nil {
		return nil, err
	}

	result, err := api.ListUsersPaginated(api.ListUsersRequest{
		Caller:     caller,
		Pagination: pagination,
		All:        input.All,
		Search:     input.Search,
	})
	if err != nil {
		return nil, err
	}

	return &ListUsersOutput{Body: result}, nil
}

func (c *UserController) HandleCreateUser(ctx context.Context, input *CreateUserInput) (*CreateUserOutput, error) {
	if err := validator.ValidatePayloadOrError(input.Body); err != nil {
		return nil, err
	}

	userID, err := api.CreateUser(api.CreateUserRequest{
		Emails:   input.Body.Emails,
		Phones:   input.Body.Phones,
		Password: input.Body.Password,
		Username: input.Body.Username,
	})
	if err != nil {
		return nil, err
	}

	return &CreateUserOutput{Location: "/v2/users/" + userID}, nil
}

func (c *UserController) HandleBulkCheckUsers(ctx context.Context, input *BulkCheckUsersInput) (*BulkCheckUsersOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := validator.ValidatePayloadOrError(input.Body); err != nil {
		return nil, err
	}

	result, err := api.BulkCheckUsers(caller, input.Body.UserIDs)
	if err != nil {
		return nil, err
	}

	return &BulkCheckUsersOutput{Body: result}, nil
}
