package v2

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/server/middlewares"
)

// registerUserRoutes registers all user routes under /v2/users
func (r *V2Router) registerUserRoutes(v2API huma.API) {
	cfg := r.app.Config()
	ctrl := r.registry.GetUserController()

	users := huma.NewGroup(v2API, "/users")
	users.UseMiddleware(middleware.HumaValidateFrontendOrigins(cfg))
	users.UseMiddleware(middleware.HumaCheckSession(r.app))

	adminUsers := huma.NewGroup(users)
	adminUsers.UseMiddleware(middleware.HumaCheckAdmin(r.app))

	userActionAPI := huma.NewGroup(users, "/{user_id}")
	userActionAPI.UseMiddleware(middleware.HumaSelectUserFromSession("param"))

	userDataLockAdminAPI := huma.NewGroup(userActionAPI, "/userdata/lock")
	userDataLockAdminAPI.UseMiddleware(middleware.HumaCheckAdmin(r.app))

	userMetadataAPI := huma.NewGroup(userActionAPI, "/metadata")
	userMetadataAPI.UseMiddleware(middleware.HumaCheckAdmin(r.app))

	r.registerUserCollectionRoutes(users, adminUsers, ctrl)
	r.registerUserCoreRoutes(userActionAPI, ctrl)
	r.registerUsernameRoutes(userActionAPI, ctrl)
	r.registerEmailRoutes(userActionAPI, ctrl)
	r.registerPhoneRoutes(userActionAPI, ctrl)
	r.registerUserAuthenticatorRoutes(userActionAPI, ctrl)
	r.registerUserDataRoutes(userActionAPI, userDataLockAdminAPI, ctrl)
	r.registerUserMetadataRoutes(userMetadataAPI, ctrl)
}

func (r *V2Router) registerUserCollectionRoutes(usersAPI, adminUsersAPI huma.API, ctrl *controllerv2.UserController) {
	adminTokenMethod := r.app.Config().AdminConfig.AdminTokenMethod

	huma.Register(usersAPI, huma.Operation{
		OperationID:   "listUsers",
		Method:        http.MethodGet,
		Path:          "/",
		Summary:       "List users",
		Description:   "List users",
		Tags:          []string{"users"},
		Security:      serverHelpers.SessionSecurity(),
		DefaultStatus: http.StatusOK,
	}, ctrl.HandleListUsers)

	huma.Register(usersAPI, huma.Operation{
		OperationID:   "bulkCheckUsers",
		Method:        http.MethodPost,
		Path:          "/bulk",
		Summary:       "Bulk check users",
		Description:   "Check multiple user IDs at once. Returns the users that exist and are accessible to the session, and the IDs that were not found.",
		Tags:          []string{"users"},
		Security:      serverHelpers.SessionSecurity(),
		DefaultStatus: http.StatusOK,
	}, ctrl.HandleBulkCheckUsers)

	huma.Register(adminUsersAPI, serverHelpers.AdminOnlyOperation(huma.Operation{
		OperationID:   "createUser",
		Method:        http.MethodPost,
		Path:          "/",
		Summary:       "Create a user (Admin only)",
		Description:   "Create a user (Admin only)",
		Tags:          []string{"users"},
		Security:      serverHelpers.SessionSecurity(),
		DefaultStatus: http.StatusCreated,
	}, adminTokenMethod), ctrl.HandleCreateUser)
}
