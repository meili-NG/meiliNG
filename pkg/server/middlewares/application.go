package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	mctx "github.com/meili-NG/meiliNG/v2/pkg/server/controllers/context"
)

func getApplicationID(c *fiber.Ctx) (string, error) {
	applicationID := c.Params("app_id")
	if applicationID == "" {
		return "", meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "application id is required")
	}
	return applicationID, nil
}

func fetchApplication(c *fiber.Ctx) error {
	applicationID, err := getApplicationID(c)
	if err != nil {
		return err
	}

	application, err := api.ResolveSelectedApplication(applicationID)
	if err != nil {
		return err
	}

	c.Locals("application", *application)
	c.SetUserContext(mctx.WithApplication(c.UserContext(), application))
	return nil
}

// GetApplication retrieves the selected application from Fiber locals.
func GetApplication(c *fiber.Ctx) *api.SelectedApplication {
	application, ok := c.Locals("application").(api.SelectedApplication)
	if !ok {
		return nil
	}
	return &application
}

// FetchApplication is a Fiber middleware that validates and stores the selected application.
func FetchApplication(c *fiber.Ctx) error {
	if err := fetchApplication(c); err != nil {
		return err
	}
	return c.Next()
}

func checkApplicationOwnership(c *fiber.Ctx) error {
	application := GetApplication(c)
	if application == nil {
		var err error
		application, err = api.ResolveSelectedApplication(c.Params("app_id"))
		if err != nil {
			return err
		}
	}

	session := GetPrincipal(c)
	if session == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session is required")
	}
	if session.IsAdmin() {
		return nil
	}
	if !application.HasOwner || !session.HasUser(application.OwnerID) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "you are not owner of this application")
	}
	return nil
}

// CheckApplicationOwnership is a Fiber middleware that checks if user owns the application.
func CheckApplicationOwnership(c *fiber.Ctx) error {
	if err := checkApplicationOwnership(c); err != nil {
		return err
	}
	return c.Next()
}

func validateApplicationOwnership(c *fiber.Ctx, userIDLocation string) error {
	application := GetApplication(c)
	if application == nil {
		var err error
		application, err = api.ResolveSelectedApplication(c.Params("app_id"))
		if err != nil {
			return err
		}
	}

	session := GetPrincipal(c)
	if session == nil {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "session is required")
	}

	// Admins manage any application, including instance-owned (ownerless) ones,
	// so they must bypass the per-user ownership check before it demands a
	// user_id — otherwise "user_id is required" blocks admin management of an
	// application that has no owner.
	if session.IsAdmin() {
		return nil
	}

	user, err := GetUserFromSession(c, userIDLocation)
	if err != nil {
		return err
	}

	if !application.IsOwnedBy(user.ID) {
		return meilingErrors.NewMeilingError(meilingErrors.ErrUnauthorized, "you are not owner of this application")
	}

	return nil
}

// ValidateApplicationOwnership returns a middleware that validates application ownership with user location.
func ValidateApplicationOwnership(userIDLocation string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := validateApplicationOwnership(c, userIDLocation); err != nil {
			return err
		}
		return c.Next()
	}
}
