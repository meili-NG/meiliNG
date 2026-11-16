package errors

// Type aliases.
type MeilingError = Error
type MeilingErrorType = ErrorType
type MeilingErrorSerialized = ErrorSerialized

// NewMeilingError creates a new Meiling error.
func NewMeilingError(errType ErrorType, message string) *Error {
	return New(errType, message)
}

// NewOAuth2Error creates a new OAuth2-formatted error.
func NewOAuth2Error(errType ErrorType, message string) *Error {
	return NewOAuth2(errType, message)
}

// NewInternalServerError creates a 500 error with optional cause.
func NewInternalServerError(message string, err error) *Error {
	return InternalServerError(message, err)
}
