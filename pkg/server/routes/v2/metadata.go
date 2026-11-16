package v2

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

// registerMetadataRoutes registers the admin-only GET, PUT and PATCH of a
// record's metadata on api, which must already require an admin.
func registerMetadataRoutes[I, B any](
	r *V2Router, api huma.API, name, tag string,
	get func(context.Context, *I) (*controllerv2.MetadataOutput, error),
	set, merge func(context.Context, *B) (*types.BlankBody, error),
) {
	adminTokenMethod := r.app.Config().AdminConfig.AdminTokenMethod
	for _, op := range []struct {
		id, method, summary string
		handler             any
	}{
		{"get" + name + "Metadata", http.MethodGet, "Get " + tag + " metadata (Admin only)", get},
		{"update" + name + "Metadata", http.MethodPut, "Replace " + tag + " metadata (Admin only)", set},
		{"merge" + name + "Metadata", http.MethodPatch, "Merge " + tag + " metadata (Admin only)", merge},
	} {
		operation := serverHelpers.AdminOnlyOperation(huma.Operation{
			OperationID: op.id,
			Method:      op.method,
			Path:        "/",
			Summary:     op.summary,
			Description: op.summary + ". Free-form data plugins keep on the record; core never reads it.",
			Tags:        []string{tag},
			Security:    serverHelpers.SessionSecurity(),
		}, adminTokenMethod)
		switch h := op.handler.(type) {
		case func(context.Context, *I) (*controllerv2.MetadataOutput, error):
			huma.Register(api, operation, h)
		case func(context.Context, *B) (*types.BlankBody, error):
			huma.Register(api, operation, h)
		}
	}
}
