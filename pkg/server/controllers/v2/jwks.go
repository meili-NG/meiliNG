package v2

import (
	"context"

	"github.com/go-jose/go-jose/v4"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// JWKSController handles JWKS operations
type JWKSController struct {
	controllers.Base
}

// NewJWKSController creates a new JWKS controller
func NewJWKSController(a *app.Meiling) *JWKSController {
	return &JWKSController{Base: controllers.NewBase(a)}
}

// HandleJWKS returns the JSON Web Key Set
func (c *JWKSController) HandleJWKS(ctx context.Context, input *JWKSInput) (*JWKSOutput, error) {
	jwt := c.TokenServices().JWT()
	keySet := jose.JSONWebKeySet{Keys: jwt.GetJWKs()}
	return &JWKSOutput{Body: keySet}, nil
}
