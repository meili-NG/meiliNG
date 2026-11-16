package controllers

type SessionAuthorizationHeaderInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"true"`
}

type OptionalSessionAuthorizationHeaderInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"false"`
}

type UserIDPathInput struct {
	UserID string `path:"user_id" doc:"User ID" required:"true"`
}

type AppIDPathInput struct {
	AppID string `path:"app_id" doc:"Application ID" required:"true"`
}

type UserIDQueryInput struct {
	UserID string `query:"user_id" doc:"User ID" required:"true"`
}

// OptionalUserIDQueryInput is like UserIDQueryInput but does not require the
// user_id query parameter. It is used by application-management endpoints where
// an admin acts on any application (including instance-owned ones) without a
// user context; the ownership middleware enforces user_id only for non-admins.
type OptionalUserIDQueryInput struct {
	UserID string `query:"user_id" doc:"User ID (optional for admins)" required:"false"`
}

type PageSizePaginationInput struct {
	Page int `query:"page" doc:"Page" required:"false"`
	Size int `query:"size" doc:"Page size" required:"false"`
}

type BypassPaginationInput struct {
	Bypass bool `query:"bypass" doc:"Bypass pagination" required:"false"`
}
