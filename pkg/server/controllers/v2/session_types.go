package v2

import (
	"time"

	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// ValidateSessionInput represents the input for session validation
type ValidateSessionInput struct {
	Authorization string `header:"Authorization" doc:"Session token" example:"Bearer eyJ..."`
}

// ValidateSessionOutput represents the output for session validation
type ValidateSessionOutput struct {
	Body ValidateSessionResponse
}

type ValidateSessionResponse struct {
	Renewable bool `json:"renewable" doc:"Whether the session token is currently eligible for renewal"`
}

// CreateSessionInput represents the input for session creation or renewal.
type CreateSessionInput struct {
	Authorization string `header:"Authorization" doc:"Existing session token to renew" required:"false" example:"Bearer eyJ..."`
}

// CreateSessionResponse is the response for session creation
type CreateSessionResponse struct {
	Token          string    `json:"token" doc:"The session JWT token" example:"eyJ..."`
	ExpiresAt      time.Time `json:"expiresAt" doc:"Session expiration timestamp" example:"2006-01-02T15:04:05Z"`
	RenewableAfter time.Time `json:"renewableAfter" doc:"Earliest timestamp when this session becomes eligible for renewal" example:"2006-01-01T03:04:05Z"`
	Renewed        bool      `json:"renewed" doc:"Whether an existing session token was renewed"`
}

// CreateSessionOutput wraps the session creation response
type CreateSessionOutput struct {
	Body CreateSessionResponse
}

// GetSessionDebugInput represents the input for session debug
type GetSessionDebugInput struct {
	Authorization string `header:"Authorization" doc:"Session token" example:"Bearer eyJ..."`
	Token         string `query:"token" doc:"Session Token to get debug information" required:"false"`
}

// GetSessionDebugOutput wraps the session debug response
type GetSessionDebugOutput struct {
	Body tokens.SessionPayload
}
