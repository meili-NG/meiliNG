package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

func (r *V2Router) registerEmailRoutes(userActionAPI huma.API, ctrl *controllerv2.UserController) {
	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getEmails",
		Method:      http.MethodGet,
		Path:        "/emails",
		Summary:     "Get emails",
		Description: "Get emails",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetEmails)

	huma.Register(userActionAPI, huma.Operation{
		OperationID:   "addEmail",
		Method:        http.MethodPost,
		Path:          "/emails",
		Summary:       "Add an email",
		Description:   "Add an email",
		Tags:          []string{"users"},
		Security:      serverHelpers.SessionSecurity(),
		DefaultStatus: http.StatusCreated,
	}, ctrl.HandleAddEmail)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "removeEmail",
		Method:      http.MethodDelete,
		Path:        "/emails",
		Summary:     "Remove an email",
		Description: "Remove an email",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleRemoveEmail)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "updateEmail",
		Method:      http.MethodPut,
		Path:        "/emails",
		Summary:     "Update an email",
		Description: "Update an email",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleUpdateEmail)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "verifyEmail",
		Method:      http.MethodPost,
		Path:        "/emails/verify",
		Summary:     "Verify an email",
		Description: "Verify an email",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleVerifyEmail)
}
