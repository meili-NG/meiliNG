package v2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

func (c *UserController) HandleGetUser(ctx context.Context, input *GetUserInput) (*GetUserOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	user, err := api.GetUserSerialized(caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetUserOutput{Body: user}, nil
}

func (c *UserController) HandleUpdateUser(ctx context.Context, input *UpdateUserInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.UpdateManagedUser(api.UpdateManagedUserRequest{
		Caller:           caller,
		UserID:           input.UserID,
		TwoFactorEnabled: input.Body.TwoFactorEnabled,
		MaxApplications:  input.Body.MaxApplications,
	}); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleDeleteUser(ctx context.Context, input *DeleteUserInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.DeleteManagedUser(api.DeleteManagedUserRequest{
		TokenServices: c.TokenServices(),
		Caller:        caller,
		UserID:        input.UserID,
	}); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleSignOutUser(ctx context.Context, input *SignOutUserInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.SignOutManagedUser(api.SignOutManagedUserRequest{
		TokenServices: c.TokenServices(),
		Caller:        caller,
		UserID:        input.UserID,
	}); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleSigninLogs(ctx context.Context, input *SigninLogsInput) (*SigninLogsOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	pagination, err := controllers.HTTPPagination(input.Page, input.Size, input.Bypass, 20)
	if err != nil {
		return nil, err
	}

	result, err := api.ListSigninLogsPaginated(api.ListSigninLogsRequest{
		TokenServices: c.TokenServices(),
		Caller:        caller,
		UserID:        input.UserID,
		Country:       input.Country,
		Pagination:    pagination,
	})
	if err != nil {
		return nil, err
	}

	return &SigninLogsOutput{Body: result}, nil
}

func (c *UserController) HandleSigninLogStatistics(ctx context.Context, input *SigninLogStatisticsInput) (*SigninLogStatisticsOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetSigninLogStatistics(api.GetSigninLogStatisticsRequest{
		Caller: caller,
		UserID: input.UserID,
		From:   input.From,
		To:     input.To,
	})
	if err != nil {
		return nil, err
	}

	return &SigninLogStatisticsOutput{Body: result}, nil
}

func (c *UserController) HandleFirstSigninLog(ctx context.Context, input *SigninLogEntryInput) (*SigninLogEntryOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetFirstSigninLog(c.TokenServices(), caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &SigninLogEntryOutput{Body: result}, nil
}

func (c *UserController) HandleLatestSigninLog(ctx context.Context, input *SigninLogEntryInput) (*SigninLogEntryOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetLatestSigninLog(c.TokenServices(), caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &SigninLogEntryOutput{Body: result}, nil
}

func (c *UserController) HandleCurrentSigninLog(ctx context.Context, input *SigninLogEntryInput) (*SigninLogEntryOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetCurrentSigninLog(c.TokenServices(), caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &SigninLogEntryOutput{Body: result}, nil
}

func (c *UserController) HandleForceSignout(ctx context.Context, input *ForceSignoutInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.ForceSignOutUsers(api.ForceSignOutUsersRequest{
		TokenServices: c.TokenServices(),
		Caller:        caller,
		UserID:        input.UserID,
		ID:            input.ID,
	}); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleChangePassword(ctx context.Context, input *ChangePasswordInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.ChangeUserPassword(api.ChangeUserPasswordRequest{
		Caller:           caller,
		UserID:           input.UserID,
		PreviousPassword: input.Body.PreviousPassword,
		NewPassword:      input.Body.NewPassword,
	}); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleGetUsernames(ctx context.Context, input *GetUsernamesInput) (*GetUsernamesOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetUsernames(caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetUsernamesOutput{Body: result}, nil
}

func (c *UserController) HandleAddUsername(ctx context.Context, input *AddUsernameInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.AddUsernameToUser(c.Config(), caller, input.UserID, input.Body.Username); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleChangeUsername(ctx context.Context, input *ChangeUsernameInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.ChangeUsernameForUser(caller, input.UserID, input.Body.Username); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleRemoveUsername(ctx context.Context, input *RemoveUsernameInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.RemoveUsernameFromUser(caller, input.UserID, input.Username); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleGetEmails(ctx context.Context, input *GetEmailsInput) (*GetEmailsOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetUserEmails(caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetEmailsOutput{Body: result}, nil
}

func (c *UserController) HandleAddEmail(ctx context.Context, input *AddEmailInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.AddEmailToUser(caller, input.UserID, input.Body.Email, input.Body.Verified); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleRemoveEmail(ctx context.Context, input *RemoveEmailInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.RemoveEmailFromUser(caller, input.UserID, input.Email); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleUpdateEmail(ctx context.Context, input *UpdateEmailInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.UpdateUserEmail(caller, input.UserID, input.Email, input.Body); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleVerifyEmail(ctx context.Context, input *VerifyEmailInput) (*VerifyEmailOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.VerifyUserEmail(api.VerifyUserEmailRequest{
		Config:         c.Config(),
		TokenServices:  c.TokenServices(),
		Caller:         caller,
		UserID:         input.UserID,
		Email:          input.Email,
		AcceptLanguage: input.AcceptLanguage,
		Body:           input.Body,
	})
	if err != nil {
		return nil, err
	}

	return &VerifyEmailOutput{Body: result}, nil
}

func (c *UserController) HandleGetPhones(ctx context.Context, input *GetPhonesInput) (*GetPhonesOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetUserPhones(caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetPhonesOutput{Body: result}, nil
}

func (c *UserController) HandleAddPhone(ctx context.Context, input *AddPhoneInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.AddPhoneToUser(caller, input.UserID, input.Body.Phone, input.Body.Verified); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleRemovePhone(ctx context.Context, input *RemovePhoneInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.RemovePhoneFromUser(caller, input.UserID, input.Phone); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleUpdatePhone(ctx context.Context, input *UpdatePhoneInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.UpdateUserPhone(caller, input.UserID, input.Phone, input.Body); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleGetTOTP(ctx context.Context, input *GetTOTPInput) (*GetTOTPOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetUserTOTP(caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetTOTPOutput{Body: result}, nil
}

func (c *UserController) HandleAddTOTP(ctx context.Context, input *AddTOTPInput) (*AddTOTPOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.AddUserTOTP(api.AddUserTOTPRequest{
		Config:        c.Config(),
		TokenServices: c.TokenServices(),
		Caller:        caller,
		UserID:        input.UserID,
		Body:          input.Body,
	})
	if err != nil {
		return nil, err
	}

	return &AddTOTPOutput{Body: result}, nil
}

func (c *UserController) HandleRemoveTOTP(ctx context.Context, input *RemoveTOTPInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.RemoveUserTOTP(caller, input.UserID, input.TotpID); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleGetBackupCodes(ctx context.Context, input *GetBackupCodesInput) (*GetBackupCodesOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetUserBackupCodes(caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetBackupCodesOutput{Body: result}, nil
}

func (c *UserController) HandleRegenerateBackupCodes(ctx context.Context, input *RegenerateBackupCodesInput) (*RegenerateBackupCodesOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.RegenerateUserBackupCodes(api.RegenerateUserBackupCodesRequest{
		Config: c.Config(),
		Caller: caller,
		UserID: input.UserID,
	})
	if err != nil {
		return nil, err
	}

	return &RegenerateBackupCodesOutput{Body: result}, nil
}

func (c *UserController) HandleDeleteBackupCodes(ctx context.Context, input *DeleteBackupCodesInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.DeleteUserBackupCodes(caller, input.UserID); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleGetWebAuthn(ctx context.Context, input *GetWebAuthnInput) (*GetWebAuthnOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetUserWebAuthn(caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetWebAuthnOutput{Body: result}, nil
}

func (c *UserController) HandleAddWebAuthn(ctx context.Context, input *AddWebAuthnInput) (*AddWebAuthnOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.AddUserWebAuthn(api.AddUserWebAuthnRequest{
		TokenServices: c.TokenServices(),
		Caller:        caller,
		UserID:        input.UserID,
		Body:          input.Body,
	})
	if err != nil {
		return nil, err
	}

	return &AddWebAuthnOutput{Body: result}, nil
}

func (c *UserController) HandleDeleteWebAuthn(ctx context.Context, input *DeleteWebAuthnInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.DeleteUserWebAuthn(caller, input.UserID, input.WebAuthnID); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleGetUserData(ctx context.Context, input *GetUserDataInput) (*GetUserDataOutput, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	result, err := api.GetSerializedUserData(caller, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetUserDataOutput{Body: result}, nil
}

func (c *UserController) HandleUpdateUserData(ctx context.Context, input *UpdateUserDataInput) (*types.BlankBody, error) {
	caller, err := c.RequirePrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := api.UpdateSerializedUserData(api.UpdateUserDataRequest{
		Caller: caller,
		UserID: input.UserID,
		Body:   input.Body,
	}); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleGetLockUserData(ctx context.Context, input *GetLockUserDataInput) (*GetLockUserDataOutput, error) {
	result, err := api.GetUserDataLocks(input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetLockUserDataOutput{Body: result}, nil
}

func (c *UserController) HandleSetLockUserData(ctx context.Context, input *SetLockUserDataInput) (*types.BlankBody, error) {
	if err := api.SetUserDataLocks(input.UserID, input.Body); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleGetMetadata(ctx context.Context, input *GetMetadataInput) (*GetMetadataOutput, error) {
	result, err := api.GetUserMetadata(input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetMetadataOutput{Body: result}, nil
}

func (c *UserController) HandleUpdateMetadata(ctx context.Context, input *UpdateMetadataInput) (*types.BlankBody, error) {
	if err := api.UpdateUserMetadata(input.UserID, input.Body); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

func (c *UserController) HandleMergeMetadata(ctx context.Context, input *MergeMetadataInput) (*types.BlankBody, error) {
	if err := api.MergeUserMetadata(input.UserID, input.Body); err != nil {
		return nil, err
	}

	return &types.BlankBody{}, nil
}

// SigningKeyHandlers returns the list, add, update and remove handlers for signing
// keys of kind (database.PGPKeyType or database.SSHKeyType).
func (c *UserController) SigningKeyHandlers(kind string) (
	get func(context.Context, *GetSigningKeysInput) (*GetSigningKeysOutput, error),
	add func(context.Context, *AddSigningKeyInput) (*AddSigningKeyOutput, error),
	update func(context.Context, *UpdateSigningKeyInput) (*UpdateSigningKeyOutput, error),
	remove func(context.Context, *RemoveSigningKeyInput) (*types.BlankBody, error),
) {
	get = func(ctx context.Context, input *GetSigningKeysInput) (*GetSigningKeysOutput, error) {
		caller, err := c.RequirePrincipal(ctx)
		if err != nil {
			return nil, err
		}
		result, err := api.GetUserSigningKeys(caller, input.UserID, kind)
		if err != nil {
			return nil, err
		}
		return &GetSigningKeysOutput{Body: result}, nil
	}
	add = func(ctx context.Context, input *AddSigningKeyInput) (*AddSigningKeyOutput, error) {
		caller, err := c.RequirePrincipal(ctx)
		if err != nil {
			return nil, err
		}
		result, err := api.AddUserSigningKey(caller, input.UserID, kind, input.Body)
		if err != nil {
			return nil, err
		}
		return &AddSigningKeyOutput{Body: result}, nil
	}
	update = func(ctx context.Context, input *UpdateSigningKeyInput) (*UpdateSigningKeyOutput, error) {
		caller, err := c.RequirePrincipal(ctx)
		if err != nil {
			return nil, err
		}
		result, err := api.UpdateUserSigningKey(caller, input.UserID, kind, input.KeyID, input.Body)
		if err != nil {
			return nil, err
		}
		return &UpdateSigningKeyOutput{Body: result}, nil
	}
	remove = func(ctx context.Context, input *RemoveSigningKeyInput) (*types.BlankBody, error) {
		caller, err := c.RequirePrincipal(ctx)
		if err != nil {
			return nil, err
		}
		if err := api.RemoveUserSigningKey(caller, input.UserID, kind, input.KeyID); err != nil {
			return nil, err
		}
		return &types.BlankBody{}, nil
	}
	return get, add, update, remove
}
