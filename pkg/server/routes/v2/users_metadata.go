package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

func (r *V2Router) registerUserMetadataRoutes(userMetadataAPI huma.API, ctrl *controllerv2.UserController) {
	adminTokenMethod := r.app.Config().AdminConfig.AdminTokenMethod

	huma.Register(userMetadataAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "getMetadata",
		Method:      http.MethodGet,
		Path:        "/",
		Summary:     "Get metadata (Admin only)",
		Description: "Get metadata (Admin only)",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleGetMetadata)

	huma.Register(userMetadataAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "updateMetadata",
		Method:      http.MethodPut,
		Path:        "/",
		Summary:     "Update metadata (Admin only)",
		Description: "Update metadata (Admin only)",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleUpdateMetadata)

	huma.Register(userMetadataAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID: "mergeMetadata",
		Method:      http.MethodPatch,
		Path:        "/",
		Summary:     "Merge metadata (Admin only)",
		Description: "Merge metadata (Admin only)",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, adminTokenMethod), ctrl.HandleMergeMetadata)
}
