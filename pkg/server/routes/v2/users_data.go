package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

func (r *V2Router) registerUserDataRoutes(userActionAPI, userDataLockAdminAPI huma.API, ctrl *controllerv2.UserController) {
	adminTokenMethod := r.app.Config().AdminConfig.AdminTokenMethod

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getUserData",
		Method:      http.MethodGet,
		Path:        "/userdata",
		Summary:     "Get user data",
		Description: "Get user data",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetUserData)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "updateUserData",
		Method:      http.MethodPut,
		Path:        "/userdata",
		Summary:     "Update user data",
		Description: "Update user data",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleUpdateUserData)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getLockUserData",
		Method:      http.MethodGet,
		Path:        "/userdata/lock",
		Summary:     "Get locks for user data",
		Description: "Get locks for user data",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetLockUserData)

	huma.Register(userDataLockAdminAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "setLockUserData",
		Method:      http.MethodPut,
		Path:        "/",
		Summary:     "Put lock user data",
		Description: "Put lock user data (Admin Only)",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleSetLockUserData)
}
