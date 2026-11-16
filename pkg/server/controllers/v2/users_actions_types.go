package v2

import (
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// User Actions Input/Output types

type GetUserInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetUserOutput struct {
	Body types.UserSerialized
}

type UpdateUserInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body types.UpdateUserRequest
}

type DeleteUserInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type SignOutUserInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type SigninLogsInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	controllers.PageSizePaginationInput
	controllers.BypassPaginationInput
	Country string `query:"country" doc:"Filter logs by ISO country code" required:"false"`
}

type SigninLogsOutput struct {
	Body types.PaginatedSigninLogSerialized
}

type SigninLogStatisticsInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	From string `query:"from" doc:"Start time in RFC3339 format" required:"false"`
	To   string `query:"to" doc:"End time in RFC3339 format" required:"false"`
}

type SigninLogStatisticsOutput struct {
	Body types.SignInStatisticsResponse
}

type SigninLogEntryInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type SigninLogEntryOutput struct {
	Body types.SignInLogSerialized
}

type ForceSignoutInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	ID string `query:"id" doc:"Signin Log ID" required:"false"`
}

type ChangePasswordInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body types.ChangePasswordRequest
}

type GetUsernamesInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetUsernamesOutput struct {
	Body []string
}

type AddUsernameInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body types.AddUsernameRequest
}

type ChangeUsernameInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body types.AddUsernameRequest
}

type RemoveUsernameInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Username string `query:"username" doc:"Username" required:"true"`
}

type GetEmailsInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetEmailsOutput struct {
	Body []types.AddEmailRequest
}

type AddEmailInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body types.AddEmailRequest
}

type RemoveEmailInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Email string `query:"email" doc:"Email" required:"true"`
}

type UpdateEmailInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Email string `query:"email" doc:"Email" required:"true"`
	Body  types.UpdateEmailRequest
}

type GetPhonesInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetPhonesOutput struct {
	Body []types.AddPhoneRequest
}

type AddPhoneInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body types.AddPhoneRequest
}

type RemovePhoneInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Phone string `query:"phone" doc:"Phone" required:"true"`
}

type UpdatePhoneInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Phone string `query:"phone" doc:"Phone" required:"true"`
	Body  types.UpdatePhoneRequest
}

type GetTOTPInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetTOTPOutput struct {
	Body []types.GetTOTPResponse
}

type AddTOTPInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body types.AddTOTPRequest
}

type AddTOTPOutput struct {
	Body types.AddTOTPResponse
}

type RemoveTOTPInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	TotpID string `query:"totp_id" doc:"TOTP ID" required:"true"`
}

type GetBackupCodesInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetBackupCodesOutput struct {
	Body types.GetBackupCodesResponse
}

type RegenerateBackupCodesInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type RegenerateBackupCodesOutput struct {
	Body types.RegenerateBackupCodesResponse
}

type DeleteBackupCodesInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetWebAuthnInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetWebAuthnOutput struct {
	Body []types.GetWebAuthnResponse
}

type AddWebAuthnInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body types.AddWebAuthnRequest
}

type AddWebAuthnOutput struct {
	Body types.AddWebAuthnResponse
}

type DeleteWebAuthnInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	WebAuthnID string `query:"webauthn_id" doc:"WebAuthn ID" required:"true"`
}

type GetUserDataInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetUserDataOutput struct {
	Body types.SerializedUserData
}

type UpdateUserDataInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body types.UpdateUserDataRequest
}

type GetMetadataInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetMetadataOutput struct {
	Body map[string]interface{}
}

type UpdateMetadataInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body map[string]interface{}
}

type MergeMetadataInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body map[string]interface{}
}

type GetLockUserDataInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetLockUserDataOutput struct {
	Body map[string]interface{}
}

type SetLockUserDataInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body map[string]interface{}
}

type VerifyEmailInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	AcceptLanguage string `header:"Accept-Language" doc:"The Language for sending verification code" required:"false"`
	Email          string `query:"email" doc:"Email" required:"true"`
	Body           types.VerifyEmailRequest
}

type VerifyEmailOutput struct {
	Body types.VerifyEmailResponse
}

type GetSigningKeysInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
}

type GetSigningKeysOutput struct {
	Body []types.SigningKeyResponse
}

type AddSigningKeyInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	Body types.AddSigningKeyRequest
}

type AddSigningKeyOutput struct {
	Body types.SigningKeyResponse
}

type UpdateSigningKeyInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	KeyID string `query:"key_id" doc:"Key ID" required:"true"`
	Body  types.UpdateSigningKeyRequest
}

type UpdateSigningKeyOutput struct {
	Body types.SigningKeyResponse
}

type RemoveSigningKeyInput struct {
	controllers.SessionAuthorizationHeaderInput
	controllers.UserIDPathInput
	KeyID string `query:"key_id" doc:"Key ID" required:"true"`
}
