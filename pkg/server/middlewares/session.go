package middleware

import (
	"errors"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	mctx "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/context"
	"github.com/meili-NG/meiliNG/v2/pkg/server/webui"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// GetPrincipal returns the authenticated caller from fiber context locals.
func GetPrincipal(c *fiber.Ctx) *tokens.Principal {
	principal, _ := c.Locals("principal").(*tokens.Principal)
	return principal
}

// SetPrincipal stores the authenticated caller in fiber context locals and
// in the user context Huma handlers read.
func SetPrincipal(c *fiber.Ctx, principal *tokens.Principal) {
	c.Locals("principal", principal)
	c.SetUserContext(mctx.WithPrincipal(c.UserContext(), principal))
}

// IsAdmin reports whether the caller is an admin credential.
func IsAdmin(c *fiber.Ctx) bool {
	return GetPrincipal(c).IsAdmin()
}

// GetSelectedUser retrieves the selected user from Fiber locals.
func GetSelectedUser(c *fiber.Ctx) *api.SelectedUser {
	user, ok := c.Locals("user").(api.SelectedUser)
	if !ok {
		return nil
	}
	return &user
}

// adminPrincipal returns the admin principal token authenticates as, an admin
// token or an M2M access token for the admin audience, or nil when it is neither.
func adminPrincipal(cfg *config.MeilingConfig, tokenServices *tokens.Services, tokenType string, token string) (*tokens.Principal, error) {
	if strings.EqualFold(cfg.AdminConfig.AdminTokenMethod, tokenType) {
		if principal := webui.AdminPrincipal(cfg, tokenServices, token); principal != nil {
			return principal, nil
		}
	}

	// Check the token type before assuming it's a session token.
	// OAuth2 access tokens use "Bearer" too but are a different token type.
	jwt := tokenServices.JWT()
	privateClaims, err := jwt.ParseTokenPrivateClaims(token)
	if err != nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrInvalidToken, "failed to parse token")
	}

	// Handle M2M Authentication
	if privateClaims.TokenType == tokens.TokenTypeAccessToken && cfg.AdminConfig.Accepts(config.AdminAcceptService) && cfg.AdminConfig.AdminTokenAudience != "" {
		clientID, err := validateM2MAdminAccessToken(cfg, tokenServices, privateClaims, token)
		if err != nil {
			return nil, err
		}
		return &tokens.Principal{Kind: tokens.PrincipalService, ActorID: string(tokens.PrincipalService) + ":" + clientID}, nil
	}

	return nil, nil
}

// validateM2MAdminAccessToken decides whether an OAuth2 access token grants
// Meiling admin access. Such a token is a full admin credential, so beyond the
// signature it must:
//   - name the admin audience,
//   - be issued by this instance's own issuer, not an additional accepted one,
//   - carry an expiry that has not passed,
//   - exist in the token store and not be revoked, which also rejects a
//     validly signed token this instance never issued.
func validateM2MAdminAccessToken(cfg *config.MeilingConfig, tokenServices *tokens.Services, privateClaims *tokens.JWTGlobalPrivateClaims, token string) (clientID string, err error) {
	jwtManager := tokenServices.JWT()
	claims, err := jwtManager.ParseTokenClaims(token)
	if err != nil {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidToken, "Invalid JWT while checking for M2M Token")
	}

	// Only admins assign audiences to clients, so holding the admin audience
	// is the grant.
	if !claims.Audience.Contains(cfg.AdminConfig.AdminTokenAudience) {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "Your M2M access token lacks permission to access this resource")
	}

	if claims.Expiry == nil {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidToken, "M2M access token has no expiry")
	}
	if err := claims.Validate(jwt.Expected{Issuer: jwtManager.Issuer(), Time: time.Now()}); err != nil {
		if errors.Is(err, jwt.ErrExpired) {
			return "", meilingErrors.NewMeilingError(meilingErrors.ErrTokenExpired, "M2M access token has expired")
		}
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidToken, "M2M access token is not valid for this instance")
	}

	payload, err := tokenServices.AccessToken().Get(token)
	if err != nil {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidToken, "M2M access token was not issued by this instance")
	}
	if payload.IsRevoked() || tokenServices.AccessToken().IsRevoked(token) {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrTokenRevoked, "M2M access token has been revoked")
	}

	return payload.ClientID, nil
}

func validateSession(a *app.Meiling, c *fiber.Ctx) error {
	cfg := a.Config()
	tokenServices := a.TokenServices()
	manager := tokenServices.Session()
	method, token := tokens.ParseAuthorizationHeader(c)
	if method == "" && token == "" {
		return meilingErrors.NewMeilingError(meilingErrors.ErrNoToken, "token is missing")
	}

	if tokens.IsSessionScheme(method) {
		method = "Bearer"
	}

	if principal, err := adminPrincipal(cfg, tokenServices, method, token); err != nil {
		return err
	} else if principal != nil {
		SetPrincipal(c, principal)
		return nil
	}

	if strings.ToLower(method) == "bearer" {
		payload, err := manager.Get(token)
		if err != nil {
			return err
		} else if !payload.IsNotBlank() {
			return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "invalid token")
		} else if !payload.IsValid(manager) {
			return meilingErrors.NewMeilingError(meilingErrors.ErrTokenExpired, "token has expired")
		} else if err := api.PruneInactiveSessionUsers(&payload, manager); err != nil {
			return err
		}

		SetPrincipal(c, tokens.SessionPrincipal(&payload))
		return nil
	}

	return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "unsupported authorization method")
}

// CheckSession validates the session token and sets session in context
func CheckSession(a *app.Meiling) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := validateSession(a, c); err != nil {
			return err
		}
		return c.Next()
	}
}

// TryCheckSession attempts to validate the session but continues even if it fails.
// Useful for endpoints that optionally use session info (e.g., showing version to admins).
func TryCheckSession(a *app.Meiling) fiber.Handler {
	return func(c *fiber.Ctx) error {
		_ = validateSession(a, c)
		return c.Next()
	}
}

// validateAdmin requires an admin principal: an admin token or an M2M access
// token for the admin audience. A session is never an admin.
func validateAdmin(a *app.Meiling, c *fiber.Ctx) error {
	if GetPrincipal(c) == nil {
		if err := validateSession(a, c); err != nil {
			return err
		}
	}
	if !IsAdmin(c) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "you are not admin")
	}
	return nil
}

// CheckAdmin ensures the request is from an admin
func CheckAdmin(a *app.Meiling) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := validateAdmin(a, c); err != nil {
			return err
		}
		return c.Next()
	}
}

func getUserIDFromRequest(c *fiber.Ctx, action string) (string, error) {
	var userID string
	if action == "query" {
		userID = c.Query("user_id")
	} else if action == "param" {
		userID = c.Params("user_id")
	} else {
		panic("Invalid action on server implementation")
	}

	if userID == "" {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "user_id is required")
	}

	return userID, nil
}

// GetUserFromSession retrieves the selected user from session context validation.
func GetUserFromSession(c *fiber.Ctx, action string) (*api.SelectedUser, error) {
	principal := GetPrincipal(c)
	if principal == nil {
		return nil, meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session is not valid")
	}

	userID, err := getUserIDFromRequest(c, action)
	if err != nil {
		return nil, err
	}

	return api.ResolveSelectedUser(principal, userID)
}

func selectUserFromSession(c *fiber.Ctx, action string) error {
	user, err := GetUserFromSession(c, action)
	if err != nil {
		return err
	}

	c.Locals("user", *user)
	c.SetUserContext(mctx.WithUser(c.UserContext(), user))
	return nil
}

// SelectUserFromSession creates a middleware that loads user into context
func SelectUserFromSession(action string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := selectUserFromSession(c, action); err != nil {
			return err
		}
		return c.Next()
	}
}
