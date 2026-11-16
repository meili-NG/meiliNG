package errors

import (
	"github.com/gofiber/fiber/v2"
)

// FromFiberError creates a Meiling error from a Fiber error
func FromFiberError(fiberError *fiber.Error) *Error {
	var errType ErrorType
	switch fiberError.Code {
	case fiber.StatusNotFound:
		errType = ErrNotFound
	case fiber.StatusMethodNotAllowed:
		errType = ErrMethodNotAllowed
	default:
		return nil
	}
	return New(errType, fiberError.Message)
}

// Respond sends the error as an HTTP response using Fiber.
func Respond(c *fiber.Ctx, err *Error) error {
	return c.Status(err.GetStatus()).JSON(err.ToJSON())
}
