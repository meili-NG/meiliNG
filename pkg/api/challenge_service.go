package api

import (
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

func GetChallengeTypes(tokenServices *tokens.Services, token string, challengingFor string) ([]string, error) {
	challenge, err := tokenServices.Challenge().Get(token)
	if err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid challenge token")
	}

	if challenge.IsWebAuthnFlow {
		return []string{"webauthn"}, nil
	}

	authenticators, err := getChallengeAuthenticators(tokenServices.Config(), challenge, challengingFor)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(authenticators))
	for _, authenticator := range authenticators {
		if utils.Contains(result, authenticator.Type) {
			continue
		}
		result = append(result, authenticator.Type)
	}

	return result, nil
}

func IssueChallenge(tokenServices *tokens.Services, token string, challengeType string, challengeFor string) (types.ChallengeIssuedPayload, error) {
	if token == "" {
		return types.ChallengeIssuedPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token is required")
	}
	if challengeType == "" {
		return types.ChallengeIssuedPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "type is required")
	}

	manager := tokenServices.Challenge()
	challengeData, err := manager.Get(token)
	if err != nil {
		return types.ChallengeIssuedPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid challenge token")
	}
	if challengeData.IsWebAuthnFlow && challengeType != "webauthn" {
		return types.ChallengeIssuedPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "this challenge is for webauthn only")
	}

	matchingAuthenticators := make([]database.UserAuthenticator, 0)
	var authValidator database.UserAuthValidator
	if challengeData.IsWebAuthnFlow && challengeData.UserID == "" && challengeType == "webauthn" {
		authValidator = &database.WebAuthnValidator{}
	} else {
		matchingAuthenticators, err = getChallengeAuthenticatorsByForAndType(tokenServices.Config(), challengeData, challengeType, challengeFor)
		if err != nil {
			return types.ChallengeIssuedPayload{}, err
		}
		if len(matchingAuthenticators) == 0 {
			return types.ChallengeIssuedPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "no matching authenticator found")
		}

		authValidator, err = matchingAuthenticators[0].GetValidator()
		if err != nil {
			return types.ChallengeIssuedPayload{}, err
		}
		if authValidator == nil {
			return types.ChallengeIssuedPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "adequate validator not found")
		}
	}

	challenge, response, err := authValidator.IssueChallenge()
	if err != nil {
		return types.ChallengeIssuedPayload{}, err
	}

	challengeIDs := utils.Map(matchingAuthenticators, func(authenticator database.UserAuthenticator) string {
		return authenticator.ID.String()
	})
	challengeData.SetChallenge(challengeIDs, response, authValidator.GetExpiresAt())
	if err := manager.Set(token, challengeData); err != nil {
		return types.ChallengeIssuedPayload{}, err
	}

	return types.ChallengeIssuedPayload{
		Challenge: challenge,
		ExpiresIn: challengeData.ChallengeExpiresAt,
	}, nil
}

func ValidateChallenge(tokenServices *tokens.Services, token string, challengeType string, challengeFor string, response string) (types.ChallengeSuccessPayload, error) {
	if token == "" {
		return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token is required")
	}
	if challengeType == "" {
		return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "type is required")
	}
	if response == "" {
		return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "response is required")
	}

	manager := tokenServices.Challenge()
	challengeData, err := manager.Get(token)
	if err != nil {
		return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid challenge token")
	}

	if challengeData.IsWebAuthnFlow && challengeType != "webauthn" {
		return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "this challenge is for webauthn only")
	}

	if challengeData.IsWebAuthnFlow {
		authValidator := database.WebAuthnValidator{}
		success, err := authValidator.ValidateChallenge(response, challengeData.ChallengeResponse)
		if err != nil {
			return types.ChallengeSuccessPayload{}, err
		}
		if !success {
			return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrChallengeFailed, "invalid webauthn challenge response")
		}

		identifier := authValidator.GetIdentifier()
		if identifier == nil || *identifier == "" {
			return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "authenticator not found")
		}

		authenticator, err := findAuthenticatorByIdentifierAndType(*identifier, authValidator.Type())
		if err != nil {
			return types.ChallengeSuccessPayload{}, err
		}

		challengeData.UserID = authenticator.UserID.String()
		challengeData.ChallengeIds = []string{authenticator.ID.String()}
		challengeData.ChallengeResponse, err = authValidator.SetUserOnSession(challengeData.ChallengeResponse)
		if err != nil {
			return types.ChallengeSuccessPayload{}, meilingErrors.NewInternalServerError("failed to set user on session", err)
		}
	}

	if len(challengeData.ChallengeIds) == 0 {
		if challengeFor == "" {
			return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrChallengeIssuanceRequired, "no challenge was issued yet")
		}

		authenticators, err := getChallengeAuthenticatorsByForAndType(tokenServices.Config(), challengeData, challengeType, challengeFor)
		if err != nil {
			return types.ChallengeSuccessPayload{}, err
		}
		if len(authenticators) == 0 {
			return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "no matching authenticator found")
		}

		authValidator, err := authenticators[0].GetValidator()
		if err != nil {
			return types.ChallengeSuccessPayload{}, err
		}
		if authValidator == nil {
			return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrNotFound, "adequate validator not found")
		}
		if authValidator.RequireChallenge() {
			return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrChallengeIssuanceRequired, "challenge is required")
		}

		_, validatorResponse, err := authValidator.IssueChallenge()
		if err != nil {
			return types.ChallengeSuccessPayload{}, err
		}

		challengeIDs := utils.Map(authenticators, func(authenticator database.UserAuthenticator) string {
			return authenticator.ID.String()
		})
		challengeData.SetChallenge(challengeIDs, validatorResponse, authValidator.GetExpiresAt())
		if err := manager.Set(token, challengeData); err != nil {
			return types.ChallengeSuccessPayload{}, err
		}
	} else if challengeData.IsExpired() {
		return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrChallengeExpired, "challenge has expired")
	}

	authenticators, err := findAuthenticatorsByIDs(challengeData.ChallengeIds)
	if err != nil {
		return types.ChallengeSuccessPayload{}, err
	}

	var match *database.UserAuthenticator
	for _, authenticator := range authenticators {
		if authenticator.Type != challengeType {
			continue
		}

		if challengeData.IsPassed(authenticator.ID.String()) {
			continue
		}

		authValidator, err := authenticator.GetValidator()
		if err != nil {
			continue
		}

		valid, err := authValidator.ValidateChallenge(response, challengeData.ChallengeResponse)
		if err != nil || !valid {
			continue
		}

		match = &authenticator
		break
	}

	if match == nil {
		return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrChallengeFailed, "invalid challenge response")
	}

	authValidator, err := match.GetValidator()
	if err != nil {
		return types.ChallengeSuccessPayload{}, err
	}
	if err := authValidator.Update(); err != nil {
		return types.ChallengeSuccessPayload{}, err
	}

	challengeData.MarkAsPassed(match.ID.String())
	if challengeData.UserID == "" {
		challengeData.UserID = match.UserID.String()
	} else if challengeData.UserID != match.UserID.String() {
		return types.ChallengeSuccessPayload{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user mismatch")
	}

	challengeData.ResetChallenge()
	if err := manager.Set(token, challengeData); err != nil {
		return types.ChallengeSuccessPayload{}, err
	}

	return types.ChallengeSuccessPayload{Passed: true}, nil
}

// getChallengeAuthenticators returns the challenge user's usable
// authenticators for challengingFor, without types auth.signin disables.
func getChallengeAuthenticators(cfg *config.MeilingConfig, challenge tokens.ChallengeContent, challengingFor string) ([]database.UserAuthenticator, error) {
	if challenge.UserID == "" {
		return nil, nil
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}

	where := "user_id = ?"
	switch challengingFor {
	case "2fa":
		where += " AND allow_2fa = TRUE"
	case "passwordless":
		where += " AND allow_passwordless = TRUE"
	case "signin":
		where += " AND allow_sign_in = TRUE"
	}

	authenticators := make([]database.UserAuthenticator, 0)
	if err := db.Where(where, challenge.UserID).Find(&authenticators).Error; err != nil {
		return nil, err
	}

	return enabledAuthenticators(cfg, filterUsableChallengeAuthenticators(authenticators)), nil
}

func getChallengeAuthenticatorsByForAndType(cfg *config.MeilingConfig, challenge tokens.ChallengeContent, challengeType string, challengeFor string) ([]database.UserAuthenticator, error) {
	authenticators, err := getChallengeAuthenticators(cfg, challenge, challengeFor)
	if err != nil {
		return nil, err
	}

	return utils.Filter(authenticators, func(authenticator database.UserAuthenticator) bool {
		return authenticator.Type == challengeType
	}), nil
}

func filterUsableChallengeAuthenticators(authenticators []database.UserAuthenticator) []database.UserAuthenticator {
	return utils.Filter(authenticators, func(authenticator database.UserAuthenticator) bool {
		if authenticator.Type != (&database.BackupCodeValidator{}).Type() {
			return true
		}

		validator, err := authenticator.GetBackupCodeValidator()
		return err == nil && !validator.IsUsed()
	})
}
