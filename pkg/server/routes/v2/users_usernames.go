package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

func (r *V2Router) registerUsernameRoutes(userActionAPI huma.API, ctrl *controllerv2.UserController) {
	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getUsernames",
		Method:      http.MethodGet,
		Path:        "/usernames",
		Summary:     "Get usernames",
		Description: "Get usernames",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetUsernames)

	huma.Register(userActionAPI, huma.Operation{
		OperationID:   "addUsername",
		Method:        http.MethodPost,
		Path:          "/usernames",
		Summary:       "Add a username",
		Description:   "Add a username",
		Tags:          []string{"users"},
		Security:      serverHelpers.SessionSecurity(),
		DefaultStatus: http.StatusCreated,
	}, ctrl.HandleAddUsername)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "changeUsername",
		Method:      http.MethodPut,
		Path:        "/usernames",
		Summary:     "Change username",
		Description: "Change username",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleChangeUsername)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "removeUsername",
		Method:      http.MethodDelete,
		Path:        "/usernames",
		Summary:     "Remove a username",
		Description: "Remove a username",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleRemoveUsername)
}
