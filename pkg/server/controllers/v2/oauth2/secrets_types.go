package oauth2

import (
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// GetSecretsInput represents the input for getting client secrets
type GetSecretsInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	controllers.OptionalUserIDQueryInput
}

// GetSecretsOutput represents the output for getting client secrets
type GetSecretsOutput struct {
	Body []types.ClientSecretSerialized
}

// CreateSecretInput represents the input for creating a client secret
type CreateSecretInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	controllers.OptionalUserIDQueryInput
	Body types.CreateClientSecretRequest
}

// CreateSecretOutput represents the output for creating a client secret
type CreateSecretOutput struct {
	Body types.ClientSecretSerialized
}

// DeleteSecretInput represents the input for deleting a client secret
type DeleteSecretInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	controllers.OptionalUserIDQueryInput
	SecretID string `query:"secret_id" doc:"Secret ID" required:"true"`
}
