package oauth2

import (
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// GetAudiencesInput represents the input for listing a client's audiences
type GetAudiencesInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
}

// GetAudiencesOutput represents the output for listing a client's audiences
type GetAudiencesOutput struct {
	Body []types.ClientAudienceSerialized
}

// AssignAudienceInput represents the input for assigning a registered audience
// to a client
type AssignAudienceInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	Body types.AssignClientAudienceRequest
}

// AssignAudienceOutput represents the output for assigning an audience
type AssignAudienceOutput struct {
	Body types.ClientAudienceSerialized
}

// UnassignAudienceInput represents the input for revoking a client's audience
type UnassignAudienceInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.AppIDPathInput
	AudienceID string `query:"audienceId" doc:"Assignment ID from the client's audience list, or the audience ID itself" required:"true"`
}

// ListAudienceCatalogInput represents the input for listing registered audiences
type ListAudienceCatalogInput struct {
	controllers.SessionAuthorizationHeaderInput
}

// ListAudienceCatalogOutput represents the output for listing registered audiences
type ListAudienceCatalogOutput struct {
	Body []types.AudienceSerialized
}

// AudienceIDPathInput carries the audience ID from the path
type AudienceIDPathInput struct {
	AudienceID string `path:"audience_id" doc:"Audience ID" required:"true"`
}

// GetAudienceInput represents the input for reading one registered audience
type GetAudienceInput struct {
	controllers.SessionAuthorizationHeaderInput
	AudienceIDPathInput
}

// AudienceOutput represents the output carrying one registered audience
type AudienceOutput struct {
	Body types.AudienceSerialized
}

// CreateAudienceCatalogInput represents the input for registering an audience
type CreateAudienceCatalogInput struct {
	controllers.SessionAuthorizationHeaderInput
	Body types.CreateAudienceRequest
}

// UpdateAudienceCatalogInput represents the input for editing an audience
type UpdateAudienceCatalogInput struct {
	controllers.SessionAuthorizationHeaderInput
	AudienceIDPathInput
	Body types.UpdateAudienceRequest
}

// DeleteAudienceCatalogInput represents the input for removing an audience
type DeleteAudienceCatalogInput struct {
	controllers.SessionAuthorizationHeaderInput
	AudienceIDPathInput
}

// ListAudienceClientsOutput represents the output for listing the clients an
// audience is assigned to
type ListAudienceClientsOutput struct {
	Body []types.AudienceClientSerialized
}
