package v2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// AdminController handles administrative meta-operations that are gated purely
// by the admin check, independent of a user caller.
type AdminController struct {
	controllers.Base
}

// NewAdminController creates a new admin controller.
func NewAdminController(a *app.Meiling) *AdminController {
	return &AdminController{Base: controllers.NewBase(a)}
}

// HandleProbe is a side-effect-free endpoint whose only purpose is to confirm
// admin authorization. The admin check runs in middleware, so simply reaching
// this handler means the caller is an admin. Unlike /v2/sessions/debug, it is
// not preceded by a caller check, so a raw admin token (which is not a caller
// token) is accepted here.
func (c *AdminController) HandleProbe(ctx context.Context, input *AdminProbeInput) (*AdminProbeOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}
	return &AdminProbeOutput{Body: AdminProbeResponse{Admin: true, Kind: string(caller.Kind), Actor: caller.ActorID}}, nil
}
