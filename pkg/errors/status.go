package errors

import "net/http"

var statusCodeMap = map[ErrorType]int{
	ErrNoToken:                      http.StatusBadRequest,
	ErrCaptchaFailed:                http.StatusBadRequest,
	ErrInvalidRequest:               http.StatusBadRequest,
	ErrChallengeIssuanceRequired:    http.StatusBadRequest,
	ErrInvalidScope:                 http.StatusBadRequest,
	ErrInvalidClient:                http.StatusBadRequest,
	ErrInvalidGrant:                 http.StatusBadRequest,
	ErrUnauthorized:                 http.StatusUnauthorized,
	ErrTokenTypeMismatch:            http.StatusUnauthorized,
	ErrTokenRevoked:                 http.StatusUnauthorized,
	ErrInvalidToken:                 http.StatusUnauthorized,
	ErrUnidentifiedToken:            http.StatusUnauthorized,
	ErrTwoFactorRequired:            http.StatusUnauthorized,
	ErrTokenExpired:                 http.StatusUnauthorized,
	ErrChallengeFailed:              http.StatusUnauthorized,
	ErrSessionExpired:               http.StatusUnauthorized,
	ErrUnauthorizedClient:           http.StatusUnauthorized,
	ErrAuthorizationPending:         http.StatusUnauthorized,
	ErrExpiredToken:                 http.StatusBadRequest,
	ErrOwnershipVerificationFailed:  http.StatusUnauthorized,
	ErrSignupDisabled:               http.StatusForbidden,
	ErrAccessDenied:                 http.StatusForbidden,
	ErrNotFound:                     http.StatusNotFound,
	ErrMethodNotAllowed:             http.StatusMethodNotAllowed,
	ErrUsernameAlreadyTaken:         http.StatusConflict,
	ErrDuplicateEmail:               http.StatusConflict,
	ErrDuplicateUsername:            http.StatusConflict,
	ErrChallengeExpired:             http.StatusGone,
	ErrUserDataLocked:               http.StatusLocked,
	ErrRateLimitExceeded:            http.StatusTooManyRequests,
	ErrSlowDown:                     http.StatusTooManyRequests,
	ErrUnhandledInternalServerError: http.StatusInternalServerError,
	ErrMisconfiguredServer:          http.StatusInternalServerError,
	ErrNotImplemented:               http.StatusNotImplemented,
	ErrUnsupportedGrantType:         http.StatusNotImplemented,
	ErrUnsupportedResponseType:      http.StatusBadRequest,
	ErrInvalidTarget:                http.StatusBadRequest,
	ErrConsentRequired:              http.StatusForbidden,
	ErrLoginRequired:                http.StatusForbidden,
	ErrInsufficientScope:            http.StatusForbidden,
}

// GetStatusCode returns the HTTP status code for an error type.
func GetStatusCode(errType ErrorType) int {
	if code, ok := statusCodeMap[errType]; ok {
		return code
	}
	return 599
}
