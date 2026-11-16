package v2

import (
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// Huma Input/Output types for applications

type GetApplicationsInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.PageSizePaginationInput
	All        bool   `query:"all" doc:"Fetch all if you are admin" required:"false"`
	Owned      bool   `query:"owned" doc:"Fetch only owned applications" required:"false"`
	Authorized bool   `query:"authorized" doc:"Fetch only authorized applications (default)" required:"false"`
	UserID     string `query:"user_id" doc:"User ID (User ID to fetch owned applications of)" required:"false"`
}

type GetApplicationsOutput struct {
	Body types.PaginatedSerializedApplication
}

type CreateApplicationInput struct {
	controllers.SessionAuthorizationHeaderInput
	// UserID is optional for admins: an empty value creates an instance-owned
	// (ownerless) application. Non-admins must supply their own user id, which the
	// service layer enforces.
	UserID string `query:"user_id" doc:"User ID of the application's owner (optional for admins)" required:"false"`
	Body   types.CreateApplicationPayload
}

type CreateApplicationOutput struct {
	Location string `header:"Location" doc:"Location of the created resource"`
	Body     types.SerializedApplication
}

type GetApplicationInput struct {
	controllers.OptionalSessionAuthorizationHeaderInput
	controllers.AppIDPathInput
}

type GetApplicationOutput struct {
	Body types.SerializedApplication
}

type DeleteApplicationInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
}

type UpdateApplicationInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	Body types.UpdateApplicationPayload
}

type UnauthorizeApplicationInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	controllers.OptionalUserIDQueryInput
}

// GetApplicationPermissionLimitInput represents the input for reading what an
// application may request
type GetApplicationPermissionLimitInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
}

// SetApplicationPermissionLimitInput represents the input for replacing what an
// application may request
type SetApplicationPermissionLimitInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	Body types.SetApplicationPermissionLimitRequest
}

// ApplicationPermissionLimitOutput represents the output carrying what an
// application may request
type ApplicationPermissionLimitOutput struct {
	Body types.ApplicationPermissionLimitSerialized
}
