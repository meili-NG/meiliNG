package v2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/metadata"
)

// MetadataOutput is a record's metadata.
type MetadataOutput struct {
	Body map[string]any
}

// AppMetadataInput names an application.
type AppMetadataInput struct {
	AppID string `path:"app_id" doc:"Application ID"`
}

// AppMetadataBodyInput names an application and carries metadata.
type AppMetadataBodyInput struct {
	AppID string `path:"app_id" doc:"Application ID"`
	Body  map[string]any
}

// PermissionMetadataInput names a permission.
type PermissionMetadataInput struct {
	ID string `query:"id" doc:"Permission ID" required:"true"`
}

// PermissionMetadataBodyInput names a permission and carries metadata.
type PermissionMetadataBodyInput struct {
	ID   string `query:"id" doc:"Permission ID" required:"true"`
	Body map[string]any
}

// AudienceMetadataInput names an audience.
type AudienceMetadataInput struct {
	AudienceID string `path:"audience_id" doc:"Audience ID"`
}

// AudienceMetadataBodyInput names an audience and carries metadata.
type AudienceMetadataBodyInput struct {
	AudienceID string `path:"audience_id" doc:"Audience ID"`
	Body       map[string]any
}

// GetMetadata returns a handler reading the metadata of the record of kind
// that id picks from the input.
func GetMetadata[I any](kind metadata.Kind, id func(*I) string) func(context.Context, *I) (*MetadataOutput, error) {
	return func(_ context.Context, input *I) (*MetadataOutput, error) {
		data, err := metadata.Get(kind, id(input))
		if err != nil {
			return nil, err
		}
		return &MetadataOutput{Body: data}, nil
	}
}

// ChangeMetadata returns a handler that replaces, or with merge merges, the
// metadata of the record of kind with the input's body.
func ChangeMetadata[I any](kind metadata.Kind, merge bool, id func(*I) string, body func(*I) map[string]any) func(context.Context, *I) (*types.BlankBody, error) {
	change := metadata.Set
	if merge {
		change = metadata.Merge
	}
	return func(_ context.Context, input *I) (*types.BlankBody, error) {
		if err := change(kind, id(input), body(input)); err != nil {
			return nil, err
		}
		return &types.BlankBody{}, nil
	}
}
