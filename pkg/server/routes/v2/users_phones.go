package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

func (r *V2Router) registerPhoneRoutes(userActionAPI huma.API, ctrl *controllerv2.UserController) {
	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getPhones",
		Method:      http.MethodGet,
		Path:        "/phones",
		Summary:     "Get phones",
		Description: "Get phones",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetPhones)

	huma.Register(userActionAPI, huma.Operation{
		OperationID:   "addPhone",
		Method:        http.MethodPost,
		Path:          "/phones",
		Summary:       "Add a phone",
		Description:   "Add a phone",
		Tags:          []string{"users"},
		Security:      serverHelpers.SessionSecurity(),
		DefaultStatus: http.StatusCreated,
	}, ctrl.HandleAddPhone)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "removePhone",
		Method:      http.MethodDelete,
		Path:        "/phones",
		Summary:     "Remove a phone",
		Description: "Remove a phone",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleRemovePhone)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "updatePhone",
		Method:      http.MethodPut,
		Path:        "/phones",
		Summary:     "Update a phone",
		Description: "Update a phone",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleUpdatePhone)
}
