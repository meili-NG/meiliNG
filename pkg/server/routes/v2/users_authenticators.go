package v2

import (
	"net/http"

	"github.com/meili-NG/meiliNG/v2/internal/database"

	"github.com/danielgtaylor/huma/v2"
	controllerv2 "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/v2"
	serverHelpers "github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
)

func (r *V2Router) registerUserAuthenticatorRoutes(userActionAPI huma.API, ctrl *controllerv2.UserController) {
	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getTOTP",
		Method:      http.MethodGet,
		Path:        "/totp",
		Summary:     "Get TOTP",
		Description: "Get TOTP",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetTOTP)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "addTOTP",
		Method:      http.MethodPost,
		Path:        "/totp",
		Summary:     "Add TOTP",
		Description: "Add TOTP",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleAddTOTP)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "removeTOTP",
		Method:      http.MethodDelete,
		Path:        "/totp",
		Summary:     "Delete TOTP",
		Description: "Delete TOTP",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleRemoveTOTP)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getBackupCodes",
		Method:      http.MethodGet,
		Path:        "/backup-codes",
		Summary:     "Get backup codes",
		Description: "Get remaining backup code count",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetBackupCodes)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "regenerateBackupCodes",
		Method:      http.MethodPost,
		Path:        "/backup-codes/regenerate",
		Summary:     "Regenerate backup codes",
		Description: "Regenerate backup codes",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleRegenerateBackupCodes)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "deleteBackupCodes",
		Method:      http.MethodDelete,
		Path:        "/backup-codes",
		Summary:     "Delete backup codes",
		Description: "Delete all backup codes owned by the user",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleDeleteBackupCodes)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "getWebAuthn",
		Method:      http.MethodGet,
		Path:        "/webauthn",
		Summary:     "Get WebAuthn",
		Description: "Get WebAuthn",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleGetWebAuthn)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "addWebAuthn",
		Method:      http.MethodPost,
		Path:        "/webauthn",
		Summary:     "Add WebAuthn",
		Description: "Add WebAuthn",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleAddWebAuthn)

	huma.Register(userActionAPI, huma.Operation{
		OperationID: "deleteWebAuthn",
		Method:      http.MethodDelete,
		Path:        "/webauthn",
		Summary:     "Delete WebAuthn",
		Description: "Delete WebAuthn",
		Tags:        []string{"users"},
		Security:    serverHelpers.SessionSecurity(),
	}, ctrl.HandleDeleteWebAuthn)

	for _, key := range []struct{ kind, path, name string }{
		{database.PGPKeyType, "/pgp-keys", "PGP"},
		{database.SSHKeyType, "/ssh-keys", "SSH"},
	} {
		get, add, update, remove := ctrl.SigningKeyHandlers(key.kind)
		huma.Register(userActionAPI, huma.Operation{
			OperationID: "get" + key.name + "Keys",
			Method:      http.MethodGet,
			Path:        key.path,
			Summary:     "Get " + key.name + " keys",
			Description: "List the " + key.name + " keys registered for signing in",
			Tags:        []string{"users"},
			Security:    serverHelpers.SessionSecurity(),
		}, get)
		huma.Register(userActionAPI, huma.Operation{
			OperationID:   "add" + key.name + "Key",
			Method:        http.MethodPost,
			Path:          key.path,
			Summary:       "Add " + key.name + " key",
			Description:   "Register a " + key.name + " public key for signing in with a signature over a challenge",
			Tags:          []string{"users"},
			Security:      serverHelpers.SessionSecurity(),
			DefaultStatus: http.StatusCreated,
		}, add)
		huma.Register(userActionAPI, huma.Operation{
			OperationID: "update" + key.name + "Key",
			Method:      http.MethodPatch,
			Path:        key.path,
			Summary:     "Update " + key.name + " key",
			Description: "Change a " + key.name + " key's note, or whether it is published",
			Tags:        []string{"users"},
			Security:    serverHelpers.SessionSecurity(),
		}, update)
		huma.Register(userActionAPI, huma.Operation{
			OperationID: "remove" + key.name + "Key",
			Method:      http.MethodDelete,
			Path:        key.path,
			Summary:     "Delete " + key.name + " key",
			Description: "Delete a " + key.name + " key",
			Tags:        []string{"users"},
			Security:    serverHelpers.SessionSecurity(),
		}, remove)
	}
}
