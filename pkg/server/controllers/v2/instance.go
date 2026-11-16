package v2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/auth"
	"github.com/meili-NG/meiliNG/v2/pkg/captcha"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// InstanceController describes the instance to clients.
type InstanceController struct {
	controllers.Base
}

// NewInstanceController creates a new instance controller
func NewInstanceController(a *app.Meiling) *InstanceController {
	return &InstanceController{Base: controllers.NewBase(a)}
}

// HandleGetInstance returns the public instance identity.
func (c *InstanceController) HandleGetInstance(ctx context.Context, input *InstanceInput) (*InstanceOutput, error) {
	cfg := c.Config()
	info := InstanceInfo{
		Name:        cfg.InstanceConfig.Name,
		Description: cfg.ServiceDescription(),
		LogoURL:     cfg.InstanceConfig.LogoURL,
		SupportURL:  cfg.InstanceConfig.SupportURL,
		SignIn: SignInInfo{
			Username: !cfg.AuthConfig.SignIn.DisableUsername,
			Email:    !cfg.AuthConfig.SignIn.DisableEmail,
			Passkey:  auth.PasskeyEnabled(cfg),
		},
	}

	verifier, err := captcha.For(cfg)
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("captcha provider failed", err)
	}
	if verifier != nil {
		widget := verifier.Widget()
		info.Captcha = &widget
	}
	return &InstanceOutput{Body: info}, nil
}

// HandleGetKeyOwner tells who owns a public signing key.
func (c *InstanceController) HandleGetKeyOwner(ctx context.Context, input *KeyOwnerInput) (*KeyOwnerOutput, error) {
	owner, err := api.PublicKeyOwner(input.Fingerprint)
	if err != nil {
		return nil, err
	}
	if owner == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "no public key has this fingerprint")
	}
	return &KeyOwnerOutput{Body: KeyOwner{Type: owner.Type, Fingerprint: owner.Fingerprint, Username: owner.Username}}, nil
}
