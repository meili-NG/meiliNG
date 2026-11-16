package helpers_test

import (
	"context"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gofiber/fiber/v2"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	oauth2controllers "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2/oauth2"
	"github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

func TestEmbeddedControllerInputsPreserveOpenAPIParameters(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	api := helpers.NewHumaAPI(app, "Meiling")

	huma.Register(api, huma.Operation{
		OperationID: "embedded-user-get",
		Method:      "GET",
		Path:        "/users/{user_id}",
		Security:    helpers.SessionSecurity(),
	}, func(ctx context.Context, input *controllerv2.GetUserInput) (*controllerv2.GetUserOutput, error) {
		return &controllerv2.GetUserOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "embedded-oauth2-secret-create",
		Method:      "POST",
		Path:        "/apps/{app_id}/oauth2/secrets",
		Security:    helpers.SessionSecurity(),
	}, func(ctx context.Context, input *oauth2controllers.CreateSecretInput) (*oauth2controllers.CreateSecretOutput, error) {
		return &oauth2controllers.CreateSecretOutput{}, nil
	})

	userOp := api.OpenAPI().Paths["/users/{user_id}"].Get
	if userOp == nil {
		t.Fatal("missing embedded user operation")
	}

	hasUserID := false
	for _, param := range userOp.Parameters {
		if param.In == "header" && param.Name == "Authorization" {
			t.Fatalf("embedded user operation still documents Authorization header: %#v", userOp.Parameters)
		}
		if param.In == "path" && param.Name == "user_id" {
			hasUserID = true
		}
	}
	if !hasUserID {
		t.Fatalf("embedded user operation missing user_id path param: %#v", userOp.Parameters)
	}

	secretOp := api.OpenAPI().Paths["/apps/{app_id}/oauth2/secrets"].Post
	if secretOp == nil {
		t.Fatal("missing embedded oauth2 secret operation")
	}

	hasAppID := false
	hasUserQuery := false
	for _, param := range secretOp.Parameters {
		if param.In == "header" && param.Name == "Authorization" {
			t.Fatalf("embedded oauth2 operation still documents Authorization header: %#v", secretOp.Parameters)
		}
		if param.In == "path" && param.Name == "app_id" {
			hasAppID = true
		}
		if param.In == "query" && param.Name == "user_id" {
			hasUserQuery = true
		}
	}
	if !hasAppID || !hasUserQuery {
		t.Fatalf("embedded oauth2 operation params = %#v, want app_id path and user_id query", secretOp.Parameters)
	}
	if secretOp.RequestBody == nil || secretOp.RequestBody.Content["application/json"] == nil {
		t.Fatalf("embedded oauth2 operation request body = %#v, want application/json schema", secretOp.RequestBody)
	}
}
