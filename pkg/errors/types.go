package errors

// ErrorType represents a Meiling error type.
type ErrorType string

// General errors.
const (
	ErrUnauthorized                 ErrorType = "unauthorized"
	ErrTokenTypeMismatch            ErrorType = "token_type_mismatch"
	ErrInvalidToken                 ErrorType = "invalid_token"
	ErrTokenExpired                 ErrorType = "token_expired"
	ErrNoToken                      ErrorType = "no_token"
	ErrUsernameAlreadyTaken         ErrorType = "username_already_taken"
	ErrUnidentifiedToken            ErrorType = "unidentified_token"
	ErrSignupDisabled               ErrorType = "signup_disabled"
	ErrTokenRevoked                 ErrorType = "token_revoked"
	ErrNotFound                     ErrorType = "not_found"
	ErrUnhandledInternalServerError ErrorType = "unhandled_internal_server_error"
	ErrTwoFactorRequired            ErrorType = "two_factor_required"
	ErrChallengeFailed              ErrorType = "challenge_failed"
	ErrChallengeExpired             ErrorType = "challenge_expired"
	ErrChallengeIssuanceRequired    ErrorType = "challenge_issuance_required"
	ErrMethodNotAllowed             ErrorType = "method_not_allowed"
	ErrNotImplemented               ErrorType = "not_implemented"
	ErrMisconfiguredServer          ErrorType = "misconfigured_server"
	ErrSessionExpired               ErrorType = "session_expired"
	ErrDuplicateEmail               ErrorType = "duplicate_email"
	ErrDuplicateUsername            ErrorType = "duplicate_username"
	ErrOwnershipVerificationFailed  ErrorType = "ownership_verification_failed"
	ErrUserDataLocked               ErrorType = "user_data_locked"
	ErrCaptchaFailed                ErrorType = "captcha_failed"
)

// OAuth2 errors (RFC 6749).
const (
	ErrInvalidRequest       ErrorType = "invalid_request"
	ErrInvalidScope         ErrorType = "invalid_scope"
	ErrInvalidClient        ErrorType = "invalid_client"
	ErrInvalidGrant         ErrorType = "invalid_grant"
	ErrUnauthorizedClient   ErrorType = "unauthorized_client"
	ErrRateLimitExceeded    ErrorType = "rate_limit_exceeded"
	ErrSlowDown             ErrorType = "slow_down"
	ErrAccessDenied         ErrorType = "access_denied"
	ErrAuthorizationPending ErrorType = "authorization_pending"
	ErrExpiredToken         ErrorType = "expired_token"
	ErrUnsupportedGrantType ErrorType = "unsupported_grant_type"

	ErrUnsupportedResponseType ErrorType = "unsupported_response_type"
	ErrInvalidTarget           ErrorType = "invalid_target"
	ErrConsentRequired         ErrorType = "consent_required"
	ErrLoginRequired           ErrorType = "login_required"
	ErrInsufficientScope       ErrorType = "insufficient_scope"
)
