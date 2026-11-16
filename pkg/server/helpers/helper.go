package helpers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"
	"github.com/gofiber/fiber/v2"
	mconfig "github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
)

var urlEncodedFormat = huma.Format{
	Marshal: func(w io.Writer, v any) error {
		return fmt.Errorf("application/x-www-form-urlencoded responses are not supported")
	},
	Unmarshal: func(data []byte, v any) error {
		values, err := url.ParseQuery(string(data))
		if err != nil {
			return err
		}

		payload := map[string]any{}
		for key, vals := range values {
			switch len(vals) {
			case 0:
				payload[key] = ""
			case 1:
				payload[key] = vals[0]
			default:
				payload[key] = vals
			}
		}

		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		return json.Unmarshal(raw, v)
	},
}

// SessionSecurityScheme is the name of the session security scheme in the
// OpenAPI document. Generated clients refer to it, so a distribution can
// choose its own.
var SessionSecurityScheme = ext.NewSlot("MeilingV2Session")

const adminOnlyOperationMetadataKey = "meiling/admin-only"
const adminTokenMethodMetadataKey = "meiling/admin-token-method"

func adminAuthorizationDescription(method string) string {
	if method == "" {
		method = "AdminToken"
	}

	return fmt.Sprintf(
		"Admin authorization header. Accepts `%s <token>`, or `Bearer <M2M access token>` when it names the configured admin audience.",
		method,
	)
}

// HumaConfigFor returns the Huma configuration for the instance cfg describes,
// titled by instance.name and described by instance.description.
func HumaConfigFor(cfg *mconfig.MeilingConfig) huma.Config {
	humaConfig := HumaConfig(cfg.InstanceConfig.Name)
	humaConfig.Info.Description = cfg.ServiceDescription()
	return humaConfig
}

// HumaConfig returns the Huma configuration for the Meiling API
func HumaConfig(name string) huma.Config {
	config := huma.DefaultConfig(name, "2.0.0-SNAPSHOT")
	config.Info.Description = name + " is a secure authentication and authorization service."

	config.DocsRenderer = huma.DocsRendererScalar

	// Do not add $schema links to response bodies.
	config.CreateHooks = nil

	formats := make(map[string]huma.Format, len(config.Formats)+2)
	for key, format := range config.Formats {
		formats[key] = format
	}
	formats["application/x-www-form-urlencoded"] = urlEncodedFormat
	formats["x-www-form-urlencoded"] = urlEncodedFormat
	config.Formats = formats

	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		SessionSecurityScheme.Get(): {
			Type: "apiKey",
			In:   "header",
			Name: "Authorization",
		},
		"OAuth2AccessToken": {
			Type: "apiKey",
			In:   "header",
			Name: "Authorization",
		},
	}
	config.OnAddOperation = append(config.OnAddOperation, removeDuplicateSecurityHeaderParams)

	return config
}

func removeDuplicateSecurityHeaderParams(oapi *huma.OpenAPI, op *huma.Operation) {
	if isAdminOnlyOperation(op) {
		overrideAdminAuthorizationDocs(op)
		return
	}

	if op == nil || len(op.Parameters) == 0 || len(op.Security) == 0 {
		return
	}

	securityHeaderNames := map[string]struct{}{}
	for _, requirement := range op.Security {
		for schemeName := range requirement {
			scheme := oapi.Components.SecuritySchemes[schemeName]
			if scheme == nil {
				continue
			}

			switch {
			case scheme.Type == "apiKey" && scheme.In == "header" && scheme.Name != "":
				securityHeaderNames[strings.ToLower(scheme.Name)] = struct{}{}
			case scheme.Type == "http":
				securityHeaderNames["authorization"] = struct{}{}
			}
		}
	}

	if len(securityHeaderNames) == 0 {
		return
	}

	filtered := op.Parameters[:0]
	for _, param := range op.Parameters {
		if param == nil {
			continue
		}

		if param.In == "header" {
			if _, ok := securityHeaderNames[strings.ToLower(param.Name)]; ok {
				continue
			}
		}

		filtered = append(filtered, param)
	}

	if len(filtered) == 0 {
		op.Parameters = nil
		return
	}

	op.Parameters = filtered
}

func isAdminOnlyOperation(op *huma.Operation) bool {
	if op == nil || op.Metadata == nil {
		return false
	}

	value, ok := op.Metadata[adminOnlyOperationMetadataKey]
	if !ok {
		return false
	}

	adminOnly, ok := value.(bool)
	return ok && adminOnly
}

func overrideAdminAuthorizationDocs(op *huma.Operation) {
	op.Security = nil

	filtered := make([]*huma.Param, 0, len(op.Parameters)+1)
	var authParam *huma.Param

	for _, param := range op.Parameters {
		if param == nil {
			continue
		}

		if strings.EqualFold(param.In, "header") && strings.EqualFold(param.Name, "Authorization") {
			if authParam == nil {
				authParam = param
			}
			continue
		}

		filtered = append(filtered, param)
	}

	if authParam == nil {
		authParam = &huma.Param{
			Name: "Authorization",
			In:   "header",
		}
	}

	method, _ := op.Metadata[adminTokenMethodMetadataKey].(string)
	authParam.Required = true
	authParam.Description = adminAuthorizationDescription(method)
	authParam.Schema = &huma.Schema{Type: huma.TypeString}
	authParam.Example = strings.TrimSpace(method + " your-admin-token")

	op.Parameters = append(filtered, authParam)
}

// AdminOnlyOperation marks an operation so its OpenAPI docs describe the real admin Authorization header.
func AdminOnlyOperation(op huma.Operation, adminTokenMethod string) huma.Operation {
	if op.Metadata == nil {
		op.Metadata = map[string]any{}
	}
	op.Metadata[adminOnlyOperationMetadataKey] = true
	op.Metadata[adminTokenMethodMetadataKey] = adminTokenMethod
	return op
}

// NewHumaAPI creates a new Huma API instance with the given Fiber app
func NewHumaAPI(app *fiber.App, name string) huma.API {
	return humafiber.New(app, HumaConfig(name))
}

// NewHumaAPIWithGroup creates a new Huma API instance with the given Fiber router group
func NewHumaAPIWithGroup(app *fiber.App, group fiber.Router, name string) huma.API {
	return humafiber.NewWithGroup(app, group, HumaConfig(name))
}

// UnwrapFiberCtx extracts the underlying Fiber context from a Huma context
func UnwrapFiberCtx(ctx huma.Context) *fiber.Ctx {
	return humafiber.Unwrap(ctx)
}

// SessionSecurity returns the security requirement for session-based auth
func SessionSecurity() []map[string][]string {
	return []map[string][]string{{SessionSecurityScheme.Get(): {}}}
}

// OAuth2Security returns the security requirement for OAuth2 token auth
func OAuth2Security() []map[string][]string {
	return []map[string][]string{{"OAuth2AccessToken": {}}}
}

// RequestBodyWithJSONAndForm returns a request body that advertises both JSON and urlencoded inputs.
func RequestBodyWithJSONAndForm[T any](api huma.API, required bool, description string) *huma.RequestBody {
	schema := api.OpenAPI().Components.Schemas.Schema(reflect.TypeFor[T](), true, "")

	return &huma.RequestBody{
		Description: description,
		Required:    required,
		Content: map[string]*huma.MediaType{
			"application/json": {
				Schema: schema,
			},
			"application/x-www-form-urlencoded": {
				Schema: schema,
			},
		},
	}
}

// RequestBodyWithForm returns a request body that advertises urlencoded input only.
func RequestBodyWithForm[T any](api huma.API, required bool, description string) *huma.RequestBody {
	schema := api.OpenAPI().Components.Schemas.Schema(reflect.TypeFor[T](), true, "")

	return &huma.RequestBody{
		Description: description,
		Required:    required,
		Content: map[string]*huma.MediaType{
			"application/x-www-form-urlencoded": {
				Schema: schema,
			},
		},
	}
}

// GenerateBaseUrl generates the base URL from a Fiber context
func GenerateBaseUrl(c *fiber.Ctx) string {
	return c.Protocol() + "://" + c.Hostname()
}

// GetLanguageFromCtx extracts the preferred language from the Accept-Language header
func GetLanguageFromCtx(c *fiber.Ctx) string {
	lang := c.Get("Accept-Language")
	if lang == "" || lang == "*" {
		return "en"
	}

	// if multiple languages are provided, we will only use the first one
	langs := strings.Split(lang, ",")
	lang = strings.Split(langs[0], "-")[0]

	return lang
}
