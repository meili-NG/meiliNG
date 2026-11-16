package v2

import (
	"context"
	"errors"
	"strings"

	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// SessionController handles caller-related operations
type SessionController struct {
	controllers.Base
}

// NewSessionController creates a new caller controller
func NewSessionController(a *app.Meiling) *SessionController {
	return &SessionController{Base: controllers.NewBase(a)}
}

// Handler methods

// HandleValidateSession validates a caller token
func (c *SessionController) HandleValidateSession(ctx context.Context, input *ValidateSessionInput) (*ValidateSessionOutput, error) {
	if input.Authorization == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "token is missing")
	}

	method, token := c.parseAuthHeader(input.Authorization)
	if method == "" || token == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "invalid authorization header")
	}

	manager := c.TokenServices().Session()
	payload, err := manager.Get(token)
	if err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "invalid token")
	}
	if !payload.IsNotBlank() {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "invalid token")
	}
	if !payload.IsValid(manager) {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "token has expired")
	}
	if err := api.PruneInactiveSessionUsers(&payload, manager); err != nil {
		return nil, err
	}

	return &ValidateSessionOutput{
		Body: ValidateSessionResponse{
			Renewable: manager.CanRenew(payload),
		},
	}, nil
}

// HandleCreateSession creates a new caller
func (c *SessionController) HandleCreateSession(ctx context.Context, input *CreateSessionInput) (*CreateSessionOutput, error) {
	manager := c.TokenServices().Session()

	if input.Authorization != "" {
		method, token := c.parseAuthHeader(input.Authorization)
		if !strings.EqualFold(method, "Bearer") || token == "" {
			return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "invalid authorization header")
		}

		existingPayload, err := manager.Get(token)
		if err != nil {
			var merr *meilingErrors.MeilingError
			if errors.As(err, &merr) {
				return nil, merr
			}
			return nil, meilingErrors.NewInternalServerError("failed to load caller", err)
		}
		if err := api.PruneInactiveSessionUsers(&existingPayload, manager); err != nil {
			return nil, err
		}

		payload, jwt, err := manager.Renew(token)
		if err != nil {
			var merr *meilingErrors.MeilingError
			if errors.As(err, &merr) {
				return nil, merr
			}
			return nil, meilingErrors.NewInternalServerError("failed to renew caller", err)
		}
		if err := api.UpdateSignInLogExpiry(&payload); err != nil {
			return nil, err
		}

		return &CreateSessionOutput{
			Body: CreateSessionResponse{
				Token:          jwt,
				ExpiresAt:      payload.ExpiresAt,
				RenewableAfter: manager.RenewableAfter(payload),
				Renewed:        true,
			},
		}, nil
	}

	_, jwt, err := manager.Create()
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to create caller", err)
	}

	payload, err := manager.Get(jwt)
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to load caller", err)
	}

	return &CreateSessionOutput{
		Body: CreateSessionResponse{
			Token:          jwt,
			ExpiresAt:      payload.ExpiresAt,
			RenewableAfter: manager.RenewableAfter(payload),
			Renewed:        false,
		},
	}, nil
}

// HandleGetSessionDebug gets caller debug information
// NOTE: Admin check is enforced by middleware at the route level
func (c *SessionController) HandleGetSessionDebug(ctx context.Context, input *GetSessionDebugInput) (*GetSessionDebugOutput, error) {
	token := input.Token
	if token == "" && input.Authorization != "" {
		_, token = c.parseAuthHeader(input.Authorization)
	}

	if token == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token is required")
	}

	manager := c.TokenServices().Session()
	payload, err := manager.Get(token)
	if err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "invalid token")
	}
	if !payload.IsNotBlank() {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid token")
	}

	return &GetSessionDebugOutput{Body: payload}, nil
}

// parseAuthHeader parses the Authorization header into method and token
func (c *SessionController) parseAuthHeader(header string) (method string, token string) {
	if header == "" {
		return "", ""
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}

	return parts[0], parts[1]
}
