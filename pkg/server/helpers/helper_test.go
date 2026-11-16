package helpers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gofiber/fiber/v2"
	mconfig "github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestHumaConfigAndSecurityHelpers(t *testing.T) {
	t.Parallel()

	cfg := HumaConfig("Meiling")
	if cfg.Info.Title != "Meiling" {
		t.Fatalf("title = %q", cfg.Info.Title)
	}
	if _, ok := cfg.Components.SecuritySchemes["MeilingV2Session"]; !ok {
		t.Fatalf("MeilingV2Session scheme missing")
	}
	if _, ok := cfg.Components.SecuritySchemes["OAuth2AccessToken"]; !ok {
		t.Fatalf("OAuth2AccessToken scheme missing")
	}

	session := SessionSecurity()
	if len(session) != 1 || len(session[0]["MeilingV2Session"]) != 0 {
		t.Fatalf("SessionSecurity = %#v", session)
	}

	oauth2 := OAuth2Security()
	if len(oauth2) != 1 || len(oauth2[0]["OAuth2AccessToken"]) != 0 {
		t.Fatalf("OAuth2Security = %#v", oauth2)
	}
}

func TestFiberContextHelpers(t *testing.T) {
	t.Parallel()

	app := fiber.New()

	var baseURL string
	var language string
	app.Get("/", func(c *fiber.Ctx) error {
		baseURL = GenerateBaseUrl(c)
		language = GetLanguageFromCtx(c)
		return c.SendStatus(fiber.StatusNoContent)
	})

	req := httptest.NewRequest("GET", "http://api.example.com/", nil)
	req.Header.Set("Accept-Language", "fr-CA,fr;q=0.9")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	resp.Body.Close()

	if baseURL != "http://api.example.com" {
		t.Fatalf("GenerateBaseUrl = %q", baseURL)
	}
	if language != "fr" {
		t.Fatalf("GetLanguageFromCtx = %q", language)
	}
}

func TestGetLanguageFromCtxDefaultsToEnglish(t *testing.T) {
	t.Parallel()

	app := fiber.New()

	var language string
	app.Get("/", func(c *fiber.Ctx) error {
		language = GetLanguageFromCtx(c)
		return c.SendStatus(fiber.StatusNoContent)
	})

	req := httptest.NewRequest("GET", "http://api.example.com/", nil)
	req.Header.Set("Accept-Language", "*")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	resp.Body.Close()

	if language != "en" {
		t.Fatalf("GetLanguageFromCtx default = %q", language)
	}
}

func TestHumaConfigRemovesDuplicateAuthorizationHeaderParamsForSecuredOperations(t *testing.T) {
	t.Parallel()

	type secureInput struct {
		Authorization string `header:"Authorization" doc:"Session token" required:"true"`
		UserID        string `path:"user_id" required:"true"`
	}

	type insecureInput struct {
		Authorization string `header:"Authorization" doc:"Session token" required:"true"`
	}

	app := fiber.New()
	api := NewHumaAPI(app, "Meiling")

	huma.Register(api, huma.Operation{
		OperationID: "secure",
		Method:      "GET",
		Path:        "/users/{user_id}",
		Security:    SessionSecurity(),
	}, func(ctx context.Context, input *secureInput) (*struct{}, error) {
		return &struct{}{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "insecure",
		Method:      "GET",
		Path:        "/profile",
	}, func(ctx context.Context, input *insecureInput) (*struct{}, error) {
		return &struct{}{}, nil
	})

	secureParams := api.OpenAPI().Paths["/users/{user_id}"].Get.Parameters
	for _, param := range secureParams {
		if param.In == "header" && param.Name == "Authorization" {
			t.Fatalf("secure operation still documents Authorization header: %#v", secureParams)
		}
	}

	insecureParams := api.OpenAPI().Paths["/profile"].Get.Parameters
	foundAuthorization := false
	for _, param := range insecureParams {
		if param.In == "header" && param.Name == "Authorization" {
			foundAuthorization = true
			break
		}
	}
	if !foundAuthorization {
		t.Fatalf("insecure operation should keep Authorization header: %#v", insecureParams)
	}
}

func TestAdminOnlyOperationOverridesSessionSecurityWithAdminAuthorizationHeader(t *testing.T) {
	t.Parallel()

	type adminInput struct {
		Authorization string `header:"Authorization" doc:"Session token" required:"true"`
		UserID        string `path:"user_id" required:"true"`
	}

	app := fiber.New()
	api := NewHumaAPI(app, "Meiling")
	adminTokenMethod := "Custom-Admin-Method"

	huma.Register(api, AdminOnlyOperation(huma.Operation{
		OperationID: "admin-only",
		Method:      "GET",
		Path:        "/admin/{user_id}",
		Security:    SessionSecurity(),
	}, adminTokenMethod), func(ctx context.Context, input *adminInput) (*struct{}, error) {
		return &struct{}{}, nil
	})

	op := api.OpenAPI().Paths["/admin/{user_id}"].Get
	if op.Security != nil {
		t.Fatalf("admin operation security should be overridden, got %#v", op.Security)
	}

	var authParams []*huma.Param
	for _, param := range op.Parameters {
		if param.In == "header" && param.Name == "Authorization" {
			authParams = append(authParams, param)
		}
	}

	if len(authParams) != 1 {
		t.Fatalf("expected exactly one Authorization header param, got %#v", op.Parameters)
	}

	auth := authParams[0]
	if !auth.Required {
		t.Fatalf("admin Authorization header should be required: %#v", auth)
	}
	if auth.Description != adminAuthorizationDescription(adminTokenMethod) {
		t.Fatalf("admin Authorization description = %q", auth.Description)
	}
	if auth.Example != "Custom-Admin-Method your-admin-token" {
		t.Fatalf("admin Authorization example = %#v", auth.Example)
	}
}

func TestHumaConfigForUsesBranding(t *testing.T) {
	t.Parallel()

	cfg := &mconfig.MeilingConfig{}
	cfg.InstanceConfig.Name = "Acme ID"
	if got := HumaConfigFor(cfg); got.Info.Title != "Acme ID" || got.Info.Description != cfg.ServiceDescription() {
		t.Fatalf("info = %+v", got.Info)
	}

	cfg.InstanceConfig.Description = "Acme's identity service."
	if got := HumaConfigFor(cfg).Info.Description; got != "Acme's identity service." {
		t.Fatalf("description = %q, want instance.description", got)
	}
}
