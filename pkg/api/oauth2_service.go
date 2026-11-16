package api

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/meili-NG/meiliNG/v2/pkg/auth"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/server/webui"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

type OAuth2AuthRequest struct {
	Config               *config.MeilingConfig
	TokenServices        *tokens.Services
	Caller               *tokens.Principal
	ClientID             string
	UserID               string
	ResponseType         string
	Prompt               string
	RedirectURI          string
	Scope                string
	IncludeGrantedScopes bool
	// Approve is the user's explicit approval of the permissions pending consent.
	Approve             bool
	CodeChallenge       string
	CodeChallengeMethod string
	AccessType          string
	State               string
	Nonce               string
	// MaxAge is the OIDC max_age in seconds; empty for no limit.
	MaxAge string
	// ACRValues is the OIDC acr_values: acceptable acr values, space-delimited.
	ACRValues string
}

type OAuth2AuthRedirectRequest struct {
	ClientID             string
	RedirectURI          string
	ResponseType         string
	Scope                string
	AccessType           string
	State                string
	Prompt               string
	IncludeGrantedScopes bool
	LoginHint            string
	CodeChallenge        string
	CodeChallengeMethod  string
	Display              string
	Nonce                string
	MaxAge               string
	ACRValues            string
}

const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

func translateOAuth2ClientLookupError(err error) error {
	var meilingErr *meilingErrors.Error
	if errors.As(err, &meilingErr) {
		switch meilingErr.Type {
		case meilingErrors.ErrInvalidRequest:
			return err
		case meilingErrors.ErrNotFound:
			return meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidClient, "client not found")
		default:
			return err
		}
	}

	return err
}

func BuildOAuth2AuthRedirectURL(cfg *config.MeilingConfig, req OAuth2AuthRedirectRequest) (string, error) {
	if req.ClientID == "" {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "client_id is required")
	}

	if _, err := findOAuth2ClientByID(req.ClientID); err != nil {
		return "", translateOAuth2ClientLookupError(err)
	}
	if err := validateOAuth2ImplicitAllowed(cfg, req.ResponseType); err != nil {
		return "", err
	}

	uri, err := oauth2Frontend(cfg)
	if err != nil {
		return "", err
	}

	values := uri.Query()
	values.Set("client_id", req.ClientID)
	values.Set("redirect_uri", req.RedirectURI)
	values.Set("response_type", req.ResponseType)
	values.Set("scope", req.Scope)
	if req.AccessType != "" {
		values.Set("access_type", req.AccessType)
	}
	if req.State != "" {
		values.Set("state", req.State)
	}
	if req.Prompt != "" {
		values.Set("prompt", req.Prompt)
	}
	if req.IncludeGrantedScopes {
		values.Set("include_granted_scopes", "true")
	}
	if req.LoginHint != "" {
		values.Set("login_hint", req.LoginHint)
	}
	if req.CodeChallenge != "" {
		values.Set("code_challenge", req.CodeChallenge)
	}
	if req.CodeChallengeMethod != "" {
		values.Set("code_challenge_method", req.CodeChallengeMethod)
	}
	if req.Display != "" {
		values.Set("display", req.Display)
	}
	if req.Nonce != "" {
		values.Set("nonce", req.Nonce)
	}
	if req.MaxAge != "" {
		values.Set("max_age", req.MaxAge)
	}
	if req.ACRValues != "" {
		values.Set("acr_values", req.ACRValues)
	}

	uri.RawQuery = values.Encode()
	return uri.String(), nil
}

func StartOAuth2DeviceAuthorization(cfg *config.MeilingConfig, tokenServices *tokens.Services, body types.DeviceAuthorizationRequest, authorization string) (types.DeviceAuthorizationResponse, error) {
	if tokenServices == nil {
		return types.DeviceAuthorizationResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "token services required")
	}
	if authorization != "" && strings.HasPrefix(authorization, "Basic ") {
		decoded, err := decodeBasicAuth(authorization)
		if err == nil {
			parts := strings.SplitN(decoded, ":", 2)
			if len(parts) == 2 {
				if body.ClientID == "" {
					body.ClientID = parts[0]
				}
				if body.ClientSecret == "" {
					body.ClientSecret = parts[1]
				}
			}
		}
	}
	if body.ClientID == "" {
		return types.DeviceAuthorizationResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "client_id is required")
	}

	client, err := findOAuth2ClientByID(body.ClientID)
	if err != nil {
		return types.DeviceAuthorizationResponse{}, translateOAuth2ClientLookupError(err)
	}
	if !client.ValidateClientSecret(body.ClientSecret) {
		return types.DeviceAuthorizationResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrUnauthorizedClient, "client_secret is invalid")
	}

	perms, err := resolveOAuth2PermissionsFromScope(client, body.Scope)
	if err != nil {
		return types.DeviceAuthorizationResponse{}, err
	}
	if len(perms) == 0 {
		return types.DeviceAuthorizationResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "scope is required")
	}

	accessType := body.AccessType
	if accessType == "" {
		accessType = "online"
	}
	if accessType != "online" && accessType != "offline" {
		return types.DeviceAuthorizationResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "access_type is invalid")
	}

	deviceManager := tokenServices.DeviceCode()
	var userCode string
	var deviceCode string
	for range 5 {
		userCode = tokens.GenerateDeviceUserCode()
		deviceCode, err = deviceManager.New(tokens.DeviceCodeContent{
			UserCode: userCode,
			ClientID: client.ApplicationID.String(),
			Permissions: utils.Map(perms, func(permission database.Permission) string {
				return permission.ID.String()
			}),
			Scope:        strings.Join(utils.Map(perms, func(permission database.Permission) string { return permission.Scope }), " "),
			AccessType:   accessType,
			PollInterval: 5,
		})
		if err == nil {
			break
		}
	}
	if err != nil {
		return types.DeviceAuthorizationResponse{}, meilingErrors.NewInternalServerError("failed to issue device code", err)
	}

	verificationURI, verificationURIComplete, err := buildOAuth2DeviceVerificationURIs(cfg, userCode)
	if err != nil {
		return types.DeviceAuthorizationResponse{}, err
	}

	return types.DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		ExpiresIn:               deviceManager.GetExpirationInSeconds(),
		Interval:                5,
	}, nil
}

func AuthorizeOAuth2DeviceCode(tokenServices *tokens.Services, caller *tokens.Principal, body types.DeviceAuthorizeRequest) error {
	if caller == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "caller not found")
	}
	if tokenServices == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}
	if body.UserCode == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user_code is required")
	}
	if body.UserID == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user_id is required")
	}
	if !caller.HasUser(body.UserID) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "you are not allowed to access this user")
	}

	deviceManager := tokenServices.DeviceCode()
	deviceCode, rawDeviceCode, err := deviceManager.GetByUserCode(body.UserCode)
	if err != nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user_code is invalid")
	}
	if !deviceCode.IsPending() {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "device code is already completed")
	}

	approved := false
	if body.Approve != "" {
		parsed, err := strconv.ParseBool(body.Approve)
		if err != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "approve is invalid")
		}
		approved = parsed
	}

	if !approved {
		deviceCode.Status = tokens.DeviceCodeStatusDenied
		return deviceManager.Set(rawDeviceCode, deviceCode)
	}

	client, err := findOAuth2ClientByID(deviceCode.ClientID)
	if err != nil {
		return err
	}
	user, err := findUserByID(body.UserID)
	if err != nil {
		return err
	}

	perms := make([]database.Permission, 0, len(deviceCode.Permissions))
	for _, permissionID := range deviceCode.Permissions {
		permission, err := findPermissionByID(permissionID)
		if err != nil {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "device code permissions are invalid")
		}
		perms = append(perms, *permission)
	}
	if err := requireClientAllowsPermissions(client, perms); err != nil {
		return err
	}

	log, err := client.IssueAuthorization(user, perms).IssueLog("")
	if err != nil {
		return meilingErrors.NewInternalServerError("failed to issue authorization", err)
	}

	deviceCode.Status = tokens.DeviceCodeStatusAuthorized
	deviceCode.UserID = body.UserID
	deviceCode.ConsentLogID = log.ID.String()
	return deviceManager.Set(rawDeviceCode, deviceCode)
}

func buildOAuth2DeviceVerificationURIs(cfg *config.MeilingConfig, userCode string) (string, string, error) {
	address := ""
	if cfg != nil && len(cfg.OAuth2Config.ConsentFrontends) > 0 {
		address = cfg.OAuth2Config.ConsentFrontends[0]
	}
	if address == "" && cfg != nil {
		address = cfg.ServerConfig.PublicURL + "/v2/oauth2/device/authorize"
	}
	if address == "" {
		return "", "", meilingErrors.NewInternalServerError("device verification address is not configured", nil)
	}

	uri, err := url.Parse(address)
	if err != nil {
		return "", "", meilingErrors.NewInternalServerError("device verification address is not valid", err)
	}

	verificationURI := uri.String()
	values := uri.Query()
	values.Set("user_code", userCode)
	uri.RawQuery = values.Encode()

	return verificationURI, uri.String(), nil
}

func GetOAuth2AuthConsent(req OAuth2AuthRequest) (types.UserConsentRequest, error) {
	if req.Caller == nil {
		return types.UserConsentRequest{}, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session not found")
	}

	client, err := findOAuth2ClientByID(req.ClientID)
	if err != nil {
		return types.UserConsentRequest{}, err
	}

	if err := validateOAuth2ResponseType(req.Config, req.ResponseType); err != nil {
		return types.UserConsentRequest{}, err
	}
	if err := validateOAuth2Prompt(req.Config, req.Prompt, client); err != nil {
		return types.UserConsentRequest{}, err
	}
	if err := validateOAuth2RedirectURI(req.RedirectURI, client); err != nil {
		return types.UserConsentRequest{}, err
	}

	user, err := getOAuth2UserFromSession(req.Caller, req.UserID)
	if err != nil {
		return types.UserConsentRequest{}, err
	}

	perms, err := getOAuth2PermissionsFromScope(req.Scope, req.IncludeGrantedScopes, client, user)
	if err != nil {
		return types.UserConsentRequest{}, err
	}

	pending, err := pendingOAuth2Consent(req.Prompt, client, user, perms)
	if err != nil {
		return types.UserConsentRequest{}, err
	}
	_, reauthenticate, err := oauth2Reauthentication(req, user)
	if err != nil {
		return types.UserConsentRequest{}, err
	}

	presented := make([]types.PermissionSerialized, 0, len(pending))
	for _, permission := range pending {
		presented = append(presented, permission.Serialize())
	}

	return types.UserConsentRequest{UserConsentRequired: len(pending) > 0, Permissions: presented, ReauthenticationRequired: reauthenticate}, nil
}

// pendingOAuth2Consent returns the permissions the user still has to approve.
// The consent check and the authorize operation both decide on it, so a code or
// token is never issued for something the check would have asked about.
func pendingOAuth2Consent(prompt string, client *database.OauthClient, user *database.User, perms []database.Permission) ([]database.Permission, error) {
	prompts := strings.Fields(prompt)
	forced := slices.Contains(prompts, "consent") || slices.Contains(prompts, "select_account")
	if !forced && slices.Contains(prompts, "bypass") && clientMayBypassConsent(client) {
		return nil, nil
	}

	pending, err := client.Application.ConsentPermissions(user, perms, forced)
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("failed to check granted permissions", err)
	}

	return pending, nil
}

func AuthorizeOAuth2Client(req OAuth2AuthRequest) (types.AuthorizeResponse, error) {
	if req.Caller == nil {
		return types.AuthorizeResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session not found")
	}
	if req.TokenServices == nil {
		return types.AuthorizeResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "token services required")
	}

	client, err := findOAuth2ClientByID(req.ClientID)
	if err != nil {
		return types.AuthorizeResponse{}, err
	}

	if err := validateOAuth2ResponseType(req.Config, req.ResponseType); err != nil {
		return types.AuthorizeResponse{}, err
	}
	if err := validateOAuth2Prompt(req.Config, req.Prompt, client); err != nil {
		return types.AuthorizeResponse{}, err
	}
	if err := validateOAuth2RedirectURI(req.RedirectURI, client); err != nil {
		return types.AuthorizeResponse{}, err
	}

	user, err := getOAuth2UserFromSession(req.Caller, req.UserID)
	if err != nil {
		return types.AuthorizeResponse{}, err
	}

	perms, err := getOAuth2PermissionsFromScope(req.Scope, req.IncludeGrantedScopes, client, user)
	if err != nil {
		return types.AuthorizeResponse{}, err
	}

	pending, err := pendingOAuth2Consent(req.Prompt, client, user, perms)
	if err != nil {
		return types.AuthorizeResponse{}, err
	}
	if len(pending) > 0 && (slices.Contains(strings.Fields(req.Prompt), "none") || !req.Approve) {
		return types.AuthorizeResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrConsentRequired, "user consent is required")
	}
	authContext, reauthenticate, err := oauth2Reauthentication(req, user)
	if err != nil {
		return types.AuthorizeResponse{}, err
	}
	if reauthenticate {
		return types.AuthorizeResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrLoginRequired, "the user has to sign in again for this request")
	}

	var codeChallenge *tokens.CodeChallengeState
	if req.CodeChallenge != "" {
		// RFC 7636 section 4.3: a challenge sent without a method is a plain one.
		method := tokens.PlainCodeChallenge
		if req.CodeChallengeMethod != "" {
			method, err = tokens.NewCodeChallengeMethod(req.CodeChallengeMethod)
			if err != nil {
				return types.AuthorizeResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "invalid code_challenge_method")
			}
		}
		codeChallenge = &tokens.CodeChallengeState{
			Challenge: req.CodeChallenge,
			Method:    method,
		}
	}

	accessType := req.AccessType
	if accessType == "" {
		accessType = "online"
	}

	responseTypes := strings.Split(req.ResponseType, " ")
	isImplicit := slices.Contains(responseTypes, "token") || slices.Contains(responseTypes, "id_token")

	// Validate before anything is issued, so a rejected request leaves no
	// consent log or tokens behind.
	if slices.Contains(responseTypes, "id_token") && req.Nonce == "" {
		return types.AuthorizeResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "nonce is required for id_token")
	}

	if authContext != nil {
		if err := recordApplicationSession(authContext.SID, user.ID, client.ApplicationID); err != nil {
			return types.AuthorizeResponse{}, meilingErrors.NewInternalServerError("failed to record the session", err)
		}
	}

	authorization := client.IssueAuthorization(user, perms)
	response := types.AuthorizeResponse{}
	hasResponse := false

	if slices.Contains(responseTypes, "code") {
		code, err := authorization.IssueCode(req.TokenServices, req.State, codeChallenge, accessType, req.Nonce, authContext)
		if err != nil {
			return types.AuthorizeResponse{}, meilingErrors.NewInternalServerError("failed to issue code", err)
		}
		response.Code = code
		hasResponse = true
	}

	if isImplicit {
		log, err := authorization.IssueLog("")
		if err != nil {
			return types.AuthorizeResponse{}, meilingErrors.NewInternalServerError("failed to issue log", err)
		}

		implicitAccessType := accessType
		if req.Config == nil || !req.Config.OAuth2Config.AllowImplicitRefresh {
			implicitAccessType = "online"
		}

		accessToken, refreshToken, err := log.IssueTokensWithGrantType(req.TokenServices, implicitAccessType, "implicit")
		if err != nil {
			return types.AuthorizeResponse{}, meilingErrors.NewInternalServerError("failed to issue tokens", err)
		}

		model, err := generateOAuth2BothTokensResponse(req.TokenServices, accessToken, refreshToken)
		if err != nil {
			return types.AuthorizeResponse{}, meilingErrors.NewInternalServerError("failed to generate response", err)
		}

		if slices.Contains(responseTypes, "id_token") {
			addOAuth2IDTokenResponse(req.TokenServices, model, log, req.Nonce, authContext)
		}

		response.Tokens = model
		hasResponse = true
	}

	if !hasResponse {
		return types.AuthorizeResponse{}, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "no valid response type")
	}

	return response, nil
}

// oauth2ClientCredentials fills clientID and clientSecret from HTTP Basic
// credentials where the request left them out.
func oauth2ClientCredentials(clientID, clientSecret, authorization string) (string, string) {
	if authorization != "" && strings.HasPrefix(authorization, "Basic ") {
		decoded, err := decodeBasicAuth(authorization)
		if err == nil {
			parts := strings.SplitN(decoded, ":", 2)
			if len(parts) == 2 {
				if clientID == "" {
					clientID = parts[0]
				}
				if clientSecret == "" {
					clientSecret = parts[1]
				}
			}
		}
	}

	return clientID, clientSecret
}

// authenticateOAuth2Client finds the client and checks its secret. A public
// client passes without one; callers that need a confidential client check
// that themselves.
func authenticateOAuth2Client(clientID, clientSecret string) (*database.OauthClient, error) {
	if clientID == "" {
		return nil, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "client_id is required")
	}

	client, err := findOAuth2ClientByID(clientID)
	if err != nil {
		return nil, translateOAuth2ClientLookupError(err)
	}
	if !client.ValidateClientSecret(clientSecret) {
		return nil, meilingErrors.NewOAuth2Error(meilingErrors.ErrUnauthorizedClient, "client_secret is invalid")
	}
	return client, nil
}

func ExchangeOAuth2Token(tokenServices *tokens.Services, body types.TokenRequest, authorization string) (types.TokenResponse, error) {
	// Public clients may omit the secret here (authorization_code,
	// refresh_token, device_code); client_credentials requires a confidential
	// client inside its own handler.
	body.ClientID, body.ClientSecret = oauth2ClientCredentials(body.ClientID, body.ClientSecret, authorization)
	client, err := authenticateOAuth2Client(body.ClientID, body.ClientSecret)
	if err != nil {
		return types.TokenResponse{}, err
	}

	switch body.GrantType {
	case "client_credentials":
		return handleClientCredentialsGrant(tokenServices, body, client)
	case "authorization_code":
		return handleAuthorizationCodeGrant(tokenServices, body, client)
	case "refresh_token":
		return handleRefreshTokenGrant(tokenServices, body, client)
	case deviceCodeGrantType:
		return handleDeviceCodeGrant(tokenServices, body, client)
	case "":
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "grant_type is required")
	default:
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrUnsupportedGrantType, "unsupported grant_type")
	}
}

func RevokeOAuth2Token(tokenServices *tokens.Services, token string) error {
	if token == "" {
		return meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "token is required")
	}

	// The webui.provideAdminUrl token is an opaque random string, not a JWT, so it is revoked where it is held.
	if magic := webui.SharedAdminTokenValue(tokenServices); magic != "" && magic == token {
		if err := webui.RevokeSharedAdminToken(tokenServices); err != nil {
			return meilingErrors.NewInternalServerError("failed to revoke admin token", err)
		}
		return nil
	}

	jwt := tokenServices.JWT()
	parsed, err := jwt.ParseTokenPrivateClaims(token)
	if err != nil {
		return meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "failed to parse token")
	}

	switch parsed.TokenType {
	case tokens.TokenTypeAccessToken:
		if err := tokenServices.AccessToken().Revoke(token); err != nil {
			return meilingErrors.NewInternalServerError("failed to revoke token", err)
		}
	case tokens.TokenTypeRefreshToken:
		if err := tokenServices.RefreshToken().Revoke(token); err != nil {
			return meilingErrors.NewInternalServerError("failed to revoke token", err)
		}
	default:
		return meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "token type is invalid")
	}

	return nil
}

func GetOAuth2TokenInfo(tokenServices *tokens.Services, accessToken string, refreshToken string, idToken string) (types.TokenResponse, error) {
	switch {
	case accessToken != "":
		resp, err := generateOAuth2AccessTokenInfoResponse(tokenServices, accessToken)
		if err != nil {
			return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "Invalid Token")
		}
		return withOAuth2ImpliedScope(*resp)
	case refreshToken != "":
		resp, err := generateOAuth2RefreshTokenInfoResponse(tokenServices, refreshToken)
		if err != nil {
			return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "Invalid Token")
		}
		return withOAuth2ImpliedScope(*resp)
	case idToken != "":
		resp, err := generateOAuth2IDTokenInfoResponse(tokenServices, idToken)
		if err != nil {
			return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "Invalid Token")
		}
		return *resp, nil
	default:
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "No token provided")
	}
}

func withOAuth2ImpliedScope(resp types.TokenResponse) (types.TokenResponse, error) {
	tree, err := database.LoadPermissionTree()
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to load permissions", err)
	}

	resp.ImpliedScope = strings.Join(tree.ImpliedScopes(strings.Fields(resp.Scope)), " ")
	return resp, nil
}

func GetOAuth2UserInfo(tokenServices *tokens.Services, authorization string) (tokens.IDTokenContent, error) {
	if authorization == "" {
		return tokens.IDTokenContent{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "Authorization header is required")
	}

	tokenString := authorization
	if strings.HasPrefix(authorization, "Bearer ") {
		tokenString = strings.TrimPrefix(authorization, "Bearer ")
	}

	accessToken, err := tokenServices.AccessToken().Get(tokenString)
	if err != nil {
		return tokens.IDTokenContent{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "Invalid Token")
	}

	if accessToken.ConsentLogID == "" {
		return tokens.IDTokenContent{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "Invalid Token Consent")
	}

	db, err := getConsentLogIDTokenDB()
	if err != nil {
		return tokens.IDTokenContent{}, err
	}

	var consentLog database.ApplicationConsentLog
	if err := db.First(&consentLog, "id = ?", accessToken.ConsentLogID).Error; err != nil {
		return tokens.IDTokenContent{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "Invalid Token Consent")
	}

	user, err := findUserByID(consentLog.UserID.String())
	if err != nil {
		return tokens.IDTokenContent{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "Invalid Token Consent")
	}

	consentLog.User = *user
	if consentLog.IsRevoked() {
		return tokens.IDTokenContent{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "Token is revoked")
	}
	// OpenID Connect Core 5.3: UserInfo answers only a token granted the openid scope.
	if !consentLog.HasPermissionScope("openid") {
		return tokens.IDTokenContent{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInsufficientScope, "the openid scope is required")
	}

	return consentLog.GenerateIDTokenContent("").WithClaimsNamespace(tokenServices.JWT().ClaimsNamespace()), nil
}

func validateOAuth2ResponseType(cfg *config.MeilingConfig, responseType string) error {
	if responseType == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "response_type is required")
	}

	if !utils.Contains([]string{"code", "token", "id_token", "none"}, responseType) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "response_type is invalid")
	}

	return validateOAuth2ImplicitAllowed(cfg, responseType)
}

// validateOAuth2ImplicitAllowed rejects the implicit flow when
// oauth2.disableImplicit is set.
func validateOAuth2ImplicitAllowed(cfg *config.MeilingConfig, responseType string) error {
	if cfg == nil || !cfg.OAuth2Config.DisableImplicit {
		return nil
	}

	for _, rt := range strings.Fields(responseType) {
		if rt == "token" || rt == "id_token" {
			return meilingErrors.NewOAuth2Error(meilingErrors.ErrUnsupportedResponseType, "implicit flow is disabled")
		}
	}

	return nil
}

// validateOAuth2Prompt checks prompt as the space-delimited list OpenID Connect
// Core section 3.1.2.1 defines, in which none stands alone.
func validateOAuth2Prompt(cfg *config.MeilingConfig, prompt string, client *database.OauthClient) error {
	prompts := strings.Fields(prompt)
	if len(prompts) > 1 && slices.Contains(prompts, "none") {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "prompt none cannot be combined with other values")
	}

	for _, value := range prompts {
		// bypass is not a standard prompt value, so it is an unknown one unless
		// the instance opts in.
		if value == "bypass" && (cfg == nil || !cfg.OAuth2Config.EnablePromptBypass) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "prompt is invalid")
		}

		if !utils.Contains([]string{"none", "login", "consent", "select_account", "bypass"}, value) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "prompt is invalid")
		}

		if value == "bypass" && !clientMayBypassConsent(client) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "prompt=bypass is not allowed for this client")
		}
	}

	return nil
}

func validateOAuth2RedirectURI(redirectURI string, client *database.OauthClient) error {
	if !client.ValidateRedirectURI(redirectURI) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "redirect_uri is invalid")
	}

	return nil
}

func getOAuth2UserFromSession(caller *tokens.Principal, userID string) (*database.User, error) {
	if userID == "" {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user_id is required")
	}
	if !caller.HasUser(userID) {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrAccessDenied, "you are not allowed to access this user")
	}

	return findUserByID(userID)
}

func getOAuth2PermissionsFromScope(scope string, includeGranted bool, client *database.OauthClient, user *database.User) ([]database.Permission, error) {
	permissions, err := resolveOAuth2PermissionsFromScope(client, scope)
	if err != nil {
		return nil, err
	}
	if len(permissions) == 0 {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "scope is required")
	}

	if includeGranted {
		granted, err := client.Application.AuthorizedPermissions(user)
		if err != nil {
			return nil, meilingErrors.NewInternalServerError("failed to get authorized permissions", err)
		}
		// An earlier grant the client is no longer allowed is left out, not an error.
		denied, err := client.Application.PermissionsOutsideLimit(granted)
		if err != nil {
			return nil, meilingErrors.NewInternalServerError("failed to check client permissions", err)
		}
		// Merged by identity only: the issued scope is never folded or expanded.
		skip := make(map[uuid.UUID]bool, len(permissions)+len(denied))
		for _, permission := range permissions {
			skip[permission.ID] = true
		}
		for _, permission := range denied {
			skip[permission.ID] = true
		}
		for _, permission := range granted {
			if !skip[permission.ID] {
				skip[permission.ID] = true
				permissions = append(permissions, permission)
			}
		}
	}

	return permissions, nil
}

// requireClientAllowsPermissions rejects permissions outside the limit an admin
// set on the client's application. Every path that turns a client's request or
// an earlier grant into a consent log, code or token goes through it.
func requireClientAllowsPermissions(client *database.OauthClient, permissions []database.Permission) error {
	denied, err := client.Application.PermissionsOutsideLimit(permissions)
	if err != nil {
		return meilingErrors.NewInternalServerError("failed to check client permissions", err)
	}
	if len(denied) > 0 {
		return meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidScope, "scope is not allowed for this client")
	}
	return nil
}

func resolveOAuth2PermissionsFromScope(client *database.OauthClient, scope string) ([]database.Permission, error) {
	requestedScopes := utils.Deduplicate(strings.Fields(scope))
	if len(requestedScopes) == 0 {
		return nil, nil
	}

	permissions := make([]database.Permission, 0, len(requestedScopes))
	for _, requestedScope := range requestedScopes {
		permission, err := findPermissionByScope(requestedScope)
		if err != nil {
			return nil, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidScope, "scope is invalid")
		}
		permissions = append(permissions, *permission)
	}

	if err := requireClientAllowsPermissions(client, permissions); err != nil {
		return nil, err
	}

	return permissions, nil
}

func permissionIDsToScopes(permissionIDs []string) ([]string, error) {
	if len(permissionIDs) == 0 {
		return nil, nil
	}

	scopes := make([]string, 0, len(permissionIDs))
	for _, permissionID := range permissionIDs {
		permission, err := findPermissionByID(permissionID)
		if err != nil {
			return nil, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "invalid token permissions")
		}
		scopes = append(scopes, permission.Scope)
	}

	return utils.Deduplicate(scopes), nil
}

func buildRefreshGrantAccessTokenContent(refreshToken tokens.RefreshTokenContent) (tokens.AccessTokenContent, error) {
	scopes, err := permissionIDsToScopes(refreshToken.Permissions)
	if err != nil {
		return tokens.AccessTokenContent{}, err
	}

	var audience []string
	if refreshToken.ClientID != "" {
		audience = []string{refreshToken.ClientID}
	}

	return tokens.AccessTokenContent{
		UserID:       refreshToken.UserID,
		ClientID:     refreshToken.ClientID,
		Permissions:  refreshToken.Permissions,
		ConsentLogID: refreshToken.ConsentLogID,
		GrantType:    "refresh_token",
		Audience:     audience,
		Scope:        strings.Join(scopes, " "),
	}, nil
}

func validateOAuth2TokenConsentLog(consentLogID string) error {
	if consentLogID == "" {
		return nil
	}

	consentLog, err := findConsentLogByID(consentLogID)
	if err != nil {
		return meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "invalid token")
	}
	if consentLog.IsRevoked() {
		return meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidToken, "Token is revoked")
	}

	return nil
}

func generateOAuth2AccessTokenInfoResponse(tokenServices *tokens.Services, token string) (*types.TokenResponse, error) {
	data, err := tokenServices.AccessToken().Get(token)
	if err != nil {
		return nil, err
	}

	if err := validateOAuth2TokenConsentLog(data.ConsentLogID); err != nil {
		return nil, err
	}

	scopes, err := permissionIDsToScopes(data.Permissions)
	if err != nil {
		return nil, err
	}

	return &types.TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(data.ExpiresAt.Sub(time.Now()).Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

func generateOAuth2RefreshTokenInfoResponse(tokenServices *tokens.Services, token string) (*types.TokenResponse, error) {
	data, err := tokenServices.RefreshToken().Get(token)
	if err != nil {
		return nil, err
	}

	if err := validateOAuth2TokenConsentLog(data.ConsentLogID); err != nil {
		return nil, err
	}

	scopes, err := permissionIDsToScopes(data.Permissions)
	if err != nil {
		return nil, err
	}

	return &types.TokenResponse{
		RefreshToken: token,
		TokenType:    "Bearer",
		ExpiresIn:    int(data.ExpiresAt.Sub(time.Now()).Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

func addOAuth2IDTokenResponse(tokenServices *tokens.Services, model *types.TokenResponse, log *database.ApplicationConsentLog, nonce string, auth *tokens.AuthContext) {
	if log.HasPermissionScope("openid") {
		model.IdToken, _ = log.IssueIDToken(tokenServices, nonce, auth)
	}
}

func generateOAuth2BothTokensResponse(tokenServices *tokens.Services, accessToken string, refreshToken string) (*types.TokenResponse, error) {
	model, err := generateOAuth2AccessTokenInfoResponse(tokenServices, accessToken)
	if err != nil {
		return nil, err
	}

	model.RefreshToken = refreshToken
	return model, nil
}

func handleClientCredentialsGrant(tokenServices *tokens.Services, body types.TokenRequest, client *database.OauthClient) (types.TokenResponse, error) {
	// client_credentials is a confidential-only (M2M) grant: it always requires
	// a valid, non-empty client secret, regardless of whether the client is
	// also usable as a public client for the authorization_code flow. This lets
	// one client serve both a public frontend (no secret) and a backend (secret)
	// without ever shipping the secret to the frontend.
	if !client.ValidateConfidentialClientSecret(body.ClientSecret) {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidClient, "client_credentials requires a valid client secret")
	}
	if body.Audience == "" {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "audience is required")
	}

	perms, err := resolveOAuth2PermissionsFromScope(client, body.Scope)
	if err != nil {
		return types.TokenResponse{}, err
	}

	audiences := strings.Fields(body.Audience)
	if err := validateClientCredentialsAudiences(client, audiences); err != nil {
		return types.TokenResponse{}, err
	}

	accessToken, err := tokenServices.AccessToken().New(tokens.AccessTokenContent{
		ClientID: client.ApplicationID.String(),
		Permissions: utils.Map(perms, func(permission database.Permission) string {
			return permission.ID.String()
		}),
		GrantType: "client_credentials",
		Audience:  audiences,
	})
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to create access token", err)
	}

	model, err := generateOAuth2AccessTokenInfoResponse(tokenServices, accessToken)
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to generate response", err)
	}

	return *model, nil
}

// validateClientCredentialsAudiences checks every requested audience against
// the ones an admin registered for the client. A client may not name an
// audience on its own, since the audience decides which resource server, and
// with the admin token audience Meiling itself, accepts the token.
func validateClientCredentialsAudiences(client *database.OauthClient, audiences []string) error {
	if len(audiences) == 0 {
		return meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "audience is required")
	}

	for _, audience := range audiences {
		if !client.AllowsAudience(audience) {
			return meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidTarget, "audience is not registered for this client: "+audience)
		}
	}
	return nil
}

func handleAuthorizationCodeGrant(tokenServices *tokens.Services, body types.TokenRequest, client *database.OauthClient) (types.TokenResponse, error) {
	if body.Code == "" {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "code is required")
	}

	codeManager := tokenServices.AuthorizationCode()
	authorizationCode, err := codeManager.Get(body.Code)
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "code is invalid")
	}
	if !authorizationCode.IsClient(body.ClientID) {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "client_id is invalid")
	}
	if !authorizationCode.IsValid() {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "code is invalid")
	}
	if !authorizationCode.VerifyCodeVerifier(body.CodeVerifier) {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "code_verifier is invalid")
	}
	if claimed, err := codeManager.ClaimOnce(body.Code); err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to redeem code", err)
	} else if !claimed {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "code is invalid")
	}

	user, err := findUserByID(authorizationCode.UserID)
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "user not found")
	}

	perms := make([]database.Permission, 0, len(authorizationCode.Permissions))
	for _, permissionID := range authorizationCode.Permissions {
		permission, err := findPermissionByID(permissionID)
		if err != nil {
			return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "invalid token permissions")
		}
		perms = append(perms, *permission)
	}
	if err := requireClientAllowsPermissions(client, perms); err != nil {
		return types.TokenResponse{}, err
	}

	log, err := client.IssueAuthorization(user, perms).IssueLog("")
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to issue authorization", err)
	}

	accessToken, refreshToken, err := log.IssueTokensWithGrantType(tokenServices, authorizationCode.AccessType, "authorization_code")
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to issue tokens", err)
	}

	if err := codeManager.Revoke(body.Code); err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to revoke code", err)
	}

	model, err := generateOAuth2BothTokensResponse(tokenServices, accessToken, refreshToken)
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to generate response", err)
	}

	addOAuth2IDTokenResponse(tokenServices, model, log, authorizationCode.Nonce, authorizationCode.Auth)
	return *model, nil
}

func handleDeviceCodeGrant(tokenServices *tokens.Services, body types.TokenRequest, client *database.OauthClient) (types.TokenResponse, error) {
	if body.DeviceCode == "" {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "device_code is required")
	}

	deviceManager := tokenServices.DeviceCode()
	deviceCode, err := deviceManager.Get(body.DeviceCode)
	if err != nil {
		var meilingErr *meilingErrors.Error
		if errors.As(err, &meilingErr) && meilingErr.Type == meilingErrors.ErrTokenExpired {
			return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrExpiredToken, "device_code has expired")
		}
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "device_code is invalid")
	}
	if !deviceCode.IsClient(client.ApplicationID.String()) {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "client_id is invalid")
	}

	if deviceCode.IsDenied() {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrAccessDenied, "access denied")
	}
	if deviceCode.IsPending() {
		interval := time.Duration(deviceCode.PollInterval) * time.Second
		if interval <= 0 {
			interval = 5 * time.Second
		}
		if !deviceCode.LastPolledAt.IsZero() && time.Since(deviceCode.LastPolledAt) < interval {
			deviceCode.PollInterval += 5
			deviceCode.LastPolledAt = time.Now()
			_ = deviceManager.Set(body.DeviceCode, deviceCode)
			return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrSlowDown, "slow down")
		}

		deviceCode.LastPolledAt = time.Now()
		_ = deviceManager.Set(body.DeviceCode, deviceCode)
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrAuthorizationPending, "authorization pending")
	}
	if !deviceCode.IsAuthorized() {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "device_code is invalid")
	}

	log, err := findConsentLogByID(deviceCode.ConsentLogID)
	if err != nil || log.IsRevoked() {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "device_code is invalid")
	}
	if err := requireClientAllowsPermissions(client, log.Permissions); err != nil {
		return types.TokenResponse{}, err
	}

	accessToken, refreshToken, err := log.IssueTokensWithGrantType(tokenServices, deviceCode.AccessType, deviceCodeGrantType)
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to issue tokens", err)
	}

	if err := deviceManager.Revoke(body.DeviceCode); err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to revoke device code", err)
	}
	_ = deviceManager.DeleteUserCode(deviceCode.UserCode)

	model, err := generateOAuth2BothTokensResponse(tokenServices, accessToken, refreshToken)
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to generate response", err)
	}

	return *model, nil
}

func handleRefreshTokenGrant(tokenServices *tokens.Services, body types.TokenRequest, client *database.OauthClient) (types.TokenResponse, error) {
	if body.RefreshToken == "" {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "refresh_token is required")
	}

	refreshManager := tokenServices.RefreshToken()
	refreshTokenContent, err := refreshManager.Get(body.RefreshToken)
	if err != nil {
		// A refresh token is single-use, so a replayed one revokes its consent log and every token issued under it.
		detectRefreshTokenReuse(tokenServices, body.RefreshToken)
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "refresh_token is invalid")
	}

	log, err := findConsentLogByID(refreshTokenContent.ConsentLogID)
	if err != nil || log.IsRevoked() {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "refresh_token is invalid")
	}

	if refreshTokenContent.ClientID == "" || refreshTokenContent.ClientID != body.ClientID {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "refresh_token is invalid")
	}
	// The token carries the permissions of its consent log; a limit tightened since then stops the refresh.
	if err := requireClientAllowsPermissions(client, log.Permissions); err != nil {
		return types.TokenResponse{}, err
	}

	accessTokenContent, err := buildRefreshGrantAccessTokenContent(refreshTokenContent)
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidGrant, "refresh_token is invalid")
	}

	token, err := tokenServices.AccessToken().New(accessTokenContent)
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to issue access token", err)
	}

	// Rotation: the presented refresh token is replaced and revoked, so a replay is caught as reuse.
	newRefreshToken, err := refreshManager.New(tokens.RefreshTokenContent{
		UserID:       refreshTokenContent.UserID,
		ClientID:     refreshTokenContent.ClientID,
		Permissions:  refreshTokenContent.Permissions,
		ConsentLogID: refreshTokenContent.ConsentLogID,
	})
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to issue refresh token", err)
	}

	if err := refreshManager.Revoke(body.RefreshToken); err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to revoke refresh token", err)
	}

	model, err := generateOAuth2BothTokensResponse(tokenServices, token, newRefreshToken)
	if err != nil {
		return types.TokenResponse{}, meilingErrors.NewInternalServerError("failed to generate response", err)
	}

	return *model, nil
}

// detectRefreshTokenReuse invalidates the token lineage when an
// already-revoked (rotated) refresh token is replayed. It is best-effort:
// lookup/parse failures for genuinely invalid tokens are ignored so the caller
// still returns the standard invalid_grant response.
func detectRefreshTokenReuse(tokenServices *tokens.Services, refreshToken string) {
	refreshManager := tokenServices.RefreshToken()
	if !refreshManager.IsRevoked(refreshToken) {
		return
	}

	consentLogID, err := refreshManager.ConsentLogIDIncludingRevoked(refreshToken)
	if err != nil || consentLogID == "" {
		return
	}

	consentLog, err := findConsentLogByID(consentLogID)
	if err != nil || consentLog.IsRevoked() {
		return
	}

	_ = consentLog.Revoke()
}

func decodeBasicAuth(header string) (string, error) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", nil
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

// generateOAuth2IDTokenInfoResponse checks an ID token this instance issued:
// its signature, its issuer, that it has not expired, and that the consent it
// came from still stands. ID tokens are not stored, so this is all there is.
func generateOAuth2IDTokenInfoResponse(tokenServices *tokens.Services, token string) (*types.TokenResponse, error) {
	jwtManager := tokenServices.JWT()
	private, err := jwtManager.ParseTokenPrivateClaims(token)
	if err != nil || private.TokenType != tokens.TokenTypeIDToken {
		return nil, errors.New("not an ID token")
	}

	var content tokens.IDTokenContent
	if err := jwtManager.ParseTokenCustomClaims(token, &content); err != nil {
		return nil, err
	}
	// Tokens of an additionally accepted issuer verify, but are not this
	// instance's to vouch for.
	if content.Issuer != jwtManager.Issuer() {
		return nil, errors.New("ID token from another issuer")
	}
	if content.Expiry == nil || content.Expiry.Time().Before(time.Now()) {
		return nil, errors.New("expired ID token")
	}
	if err := validateOAuth2TokenConsentLog(content.ConsentLogID); err != nil {
		return nil, err
	}

	return &types.TokenResponse{
		IdToken:   token,
		ExpiresIn: int(time.Until(content.Expiry.Time()).Seconds()),
		Scope:     content.Scope,
		Subject:   content.Subject,
		Audience:  content.Audience,
	}, nil
}

// IntrospectOAuth2Token answers an RFC 7662 introspection request. The caller
// must be a confidential client, and sees a token as active only when it was
// issued to that client or auth.Clients lets it introspect any; anything else, including
// an invalid token, is {"active": false}.
func IntrospectOAuth2Token(tokenServices *tokens.Services, body types.IntrospectTokenRequest, authorization string) (types.IntrospectionResponse, error) {
	clientID, clientSecret := oauth2ClientCredentials(body.ClientID, body.ClientSecret, authorization)
	client, err := authenticateOAuth2Client(clientID, clientSecret)
	if err != nil {
		return types.IntrospectionResponse{}, err
	}
	// Like client_credentials, this needs the client's secret even when the
	// client also serves a public frontend.
	if !client.ValidateConfidentialClientSecret(clientSecret) {
		return types.IntrospectionResponse{}, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidClient, "introspection requires a valid client secret")
	}

	kinds := []string{"access_token", "refresh_token"}
	if body.TokenTypeHint == "refresh_token" {
		kinds = []string{"refresh_token", "access_token"}
	}
	for _, kind := range kinds {
		if resp, ok := introspect(tokenServices, kind, body.Token); ok {
			if resp.ClientID != client.ApplicationID.String() && !auth.Clients.Get().IntrospectAny(context.Background(), clientPolicyInput(client)) {
				break
			}
			return resp, nil
		}
	}
	return types.IntrospectionResponse{Active: false}, nil
}

func introspect(tokenServices *tokens.Services, kind, token string) (types.IntrospectionResponse, bool) {
	var payload tokens.GlobalTokenPayload
	var userID, clientID, consentLogID string
	var permissions, audience []string
	switch kind {
	case "access_token":
		data, err := tokenServices.AccessToken().Get(token)
		if err != nil {
			return types.IntrospectionResponse{}, false
		}
		payload, userID, clientID, consentLogID, permissions, audience = data.GlobalTokenPayload, data.UserID, data.ClientID, data.ConsentLogID, data.Permissions, data.Audience
	case "refresh_token":
		data, err := tokenServices.RefreshToken().Get(token)
		if err != nil {
			return types.IntrospectionResponse{}, false
		}
		payload, userID, clientID, consentLogID, permissions = data.GlobalTokenPayload, data.UserID, data.ClientID, data.ConsentLogID, data.Permissions
	}
	if !payload.IsValid() || validateOAuth2TokenConsentLog(consentLogID) != nil {
		return types.IntrospectionResponse{}, false
	}
	claims, err := tokenServices.JWT().ParseTokenClaims(token)
	if err != nil {
		return types.IntrospectionResponse{}, false
	}
	scopes, err := permissionIDsToScopes(permissions)
	if err != nil {
		return types.IntrospectionResponse{}, false
	}

	resp := types.IntrospectionResponse{
		Active:    true,
		Scope:     strings.Join(scopes, " "),
		ClientID:  clientID,
		TokenType: kind,
		Sub:       userID,
		Aud:       audience,
		Iss:       claims.Issuer,
		Jti:       claims.ID,
	}
	if claims.Expiry != nil {
		resp.Exp = claims.Expiry.Time().Unix()
	}
	if claims.IssuedAt != nil {
		resp.Iat = claims.IssuedAt.Time().Unix()
	}
	return resp, true
}

// oauth2Reauthentication returns how the user signed into the caller's
// session, and whether the request's max_age or acr_values ask for a fresher or
// stronger sign-in than that.
func oauth2Reauthentication(req OAuth2AuthRequest, user *database.User) (*tokens.AuthContext, bool, error) {
	maxAge := -1
	if req.MaxAge != "" {
		n, err := strconv.Atoi(req.MaxAge)
		if err != nil || n < 0 {
			return nil, false, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "max_age is invalid")
		}
		maxAge = n
	}
	ctx := auth.Context(req.Caller.Session, user.ID.String())
	return ctx, auth.ReauthenticationRequired(ctx, maxAge, req.ACRValues, time.Now()), nil
}

// oauth2Frontend is where the browser is sent for the user's part of an OAuth2
// or OpenID Connect flow: the first oauth2.consentFrontends entry, else the
// built-in web UI, which can run the whole flow without a separate frontend.
func oauth2Frontend(cfg *config.MeilingConfig) (*url.URL, error) {
	primaryFrontend := ""
	if len(cfg.OAuth2Config.ConsentFrontends) > 0 {
		primaryFrontend = cfg.OAuth2Config.ConsentFrontends[0]
	}
	if primaryFrontend == "" {
		primaryFrontend = webui.OAuth2AuthFrontendURL(cfg)
	}
	if primaryFrontend == "" {
		return nil, meilingErrors.NewInternalServerError("frontend addresses are not configured", nil)
	}

	uri, err := url.Parse(primaryFrontend)
	if err != nil {
		return nil, meilingErrors.NewInternalServerError("frontend address is not valid", err)
	}
	return uri, nil
}

func clientPolicyInput(client *database.OauthClient) auth.Client {
	return auth.Client{ApplicationID: client.ApplicationID, BypassConsent: client.BypassConsent}
}

// clientMayBypassConsent asks the client policy whether prompt=bypass may
// skip the consent screen for client.
func clientMayBypassConsent(client *database.OauthClient) bool {
	return auth.Clients.Get().BypassConsent(context.Background(), clientPolicyInput(client))
}
