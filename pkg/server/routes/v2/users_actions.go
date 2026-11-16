package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

func (r *V2Router) registerUserCoreRoutes(userActionAPI huma.API, ctrl *controllerv2.UserController) {
	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getUser",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get a user",
		Description: "Get a user",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetUser)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "updateUser",
		Method:      http.MethodPut,
		Path:        "/",
		Summary:     "Update user data",
		Description: "Update user data",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleUpdateUser)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "deleteUser",
		Method:      http.MethodDelete,
		Path:        "/",
		Summary:     "Delete a user",
		Description: "Delete a user",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleDeleteUser)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "signOutUser",
		Method:      http.MethodPost,
		Path:        "/signout",
		Summary:     "Sign out this user",
		Description: "Sign out this user",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleSignOutUser)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getSigninLogs",
		Method:      http.MethodGet,
		Path:        "/logs",
		Summary:     "Get signin logs",
		Description: "Get signin logs",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleSigninLogs)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getSigninLogStatistics",
		Method:      http.MethodGet,
		Path:        "/logs/statistics",
		Summary:     "Get signin log statistics",
		Description: "Get signin log country statistics",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleSigninLogStatistics)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getFirstSigninLog",
		Method:      http.MethodGet,
		Path:        "/logs/first",
		Summary:     "Get first signin log",
		Description: "Get the first signin log for a user",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleFirstSigninLog)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getLatestSigninLog",
		Method:      http.MethodGet,
		Path:        "/logs/latest",
		Summary:     "Get latest signin log",
		Description: "Get the latest signin log for a user",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleLatestSigninLog)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getCurrentSigninLog",
		Method:      http.MethodGet,
		Path:        "/logs/current",
		Summary:     "Get current signin log",
		Description: "Get the current session signin log for a user",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleCurrentSigninLog)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "forceSignout",
		Method:      http.MethodDelete,
		Path:        "/logs",
		Summary:     "Force signout",
		Description: "Force signout",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleForceSignout)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "changePassword",
		Method:      http.MethodPut,
		Path:        "/password",
		Summary:     "Change password",
		Description: "Change password",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleChangePassword)
}
