package errors

import (
	"encoding/json"
	"fmt"
	"runtime/debug"

	pkgerrors "github.com/pkg/errors"
)

// Error represents a Meiling API error.
type Error struct {
	Type    ErrorType
	Message string

	cause      error
	stacktrace string
	isOAuth2   bool
}

// ErrorSerialized is the JSON representation of an error.
type ErrorSerialized struct {
	Type    ErrorType `json:"type"`
	Message string    `json:"message"`
}

// ErrorStackTracer is an interface for errors with stack traces.
type ErrorStackTracer interface {
	StackTrace() pkgerrors.StackTrace
}

// New creates a new Meiling error.
func New(errType ErrorType, message string) *Error {
	e := &Error{Type: errType, Message: message}
	if isDebugMode() {
		e.stacktrace = string(debug.Stack())
	}
	return e
}

// NewOAuth2 creates a new OAuth2-formatted error.
func NewOAuth2(errType ErrorType, message string) *Error {
	return New(errType, message).SetOAuth2(true)
}

// Wrap creates an error wrapping an underlying cause.
func Wrap(errType ErrorType, message string, cause error) *Error {
	e := New(errType, message)
	e.SetCause(cause)
	return e
}

// InternalServerError creates a 500 error with optional cause.
func InternalServerError(message string, cause error) *Error {
	return Wrap(ErrUnhandledInternalServerError, message, cause)
}

// Error implements the error interface.
// Unlike the response body, it always includes the cause, for logs and error reporting.
func (e *Error) Error() string {
	return joinMessage(joinMessage(string(e.Type), e.Message), e.causeMessage())
}

func (e *Error) causeMessage() string {
	if e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

func joinMessage(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + ": " + b
}

// SetCause sets the underlying error cause. The cause's text, which can carry
// SQL or driver details, reaches the response only in debug mode.
func (e *Error) SetCause(cause error) *Error {
	e.cause = cause
	if cause != nil {
		e.stacktrace = ""
		if isDebugMode() {
			if st, ok := pkgerrors.Cause(cause).(ErrorStackTracer); ok {
				e.stacktrace = fmt.Sprintf("%+v", st.StackTrace())
			}
		}
	}
	return e
}

// SetOAuth2 sets the OAuth2 mode.
func (e *Error) SetOAuth2(oauth2Mode bool) *Error {
	e.isOAuth2 = oauth2Mode
	return e
}

// IsOAuth2 returns whether this is an OAuth2 error.
func (e *Error) IsOAuth2() bool {
	return e.isOAuth2
}

// Cause returns the underlying error cause.
func (e *Error) Cause() error {
	return e.cause
}

// Unwrap implements errors.Unwrap.
func (e *Error) Unwrap() error {
	return e.cause
}

// GetStatus implements huma.StatusError interface.
func (e *Error) GetStatus() int {
	return GetStatusCode(e.Type)
}

// ToJSON returns the JSON payload for the error.
func (e *Error) ToJSON() map[string]interface{} {
	var output map[string]interface{}

	message := e.Message
	if isDebugMode() {
		message = joinMessage(message, e.causeMessage())
	}

	if e.isOAuth2 {
		output = map[string]interface{}{
			"error":             e.Type,
			"error_description": message,
			"url":               "https://tools.ietf.org/html/rfc6749#section-5.2",
		}
	} else {
		output = map[string]interface{}{
			"type":    e.Type,
			"message": message,
		}
	}

	if shouldRespondWithStacktrace() && e.stacktrace != "" {
		output["stacktrace"] = e.stacktrace
	}

	return output
}

// MarshalJSON implements json.Marshaler.
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.ToJSON())
}
