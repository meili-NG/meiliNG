package v2

// Challenge types

type ChallengeIssuedPayload struct {
	Challenge string `json:"challenge,omitempty"`
	ExpiresIn int64  `json:"expires_in,omitempty"`
}

type ChallengeSuccessPayload struct {
	Passed bool `json:"passed"`
}

type ChallengeResponsePayload struct {
	Response string `json:"response" validate:"optional"`
}

// Huma Input/Output types

// GetChallengeInput represents the input for getting challenge methods
type GetChallengeInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"false"`
	Token         string `query:"token" doc:"Challenge Token issued from signin or challenge requesting endpoint" required:"true"`
	For           string `query:"for" doc:"The type of challenges you are trying to prove for" enum:"2fa,passwordless,signin" required:"false"`
}

// GetChallengeOutput represents the output for challenge methods
type GetChallengeOutput struct {
	Body []string
}

// IssueChallengeInput represents the input for issuing a challenge
type IssueChallengeInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"false"`
	Token         string `query:"token" doc:"Challenge Token issued from signin or challenge requesting endpoint" required:"true"`
	Type          string `query:"type" doc:"Authenticator type: password, totp, webauthn, backup_code, pgp, ssh, or one a distribution adds" required:"true"`
	For           string `query:"for" doc:"The challenge target that you want to do for" enum:"passwordless,2fa,signin" required:"false"`
}

// IssueChallengeOutput represents the output for issuing a challenge
type IssueChallengeOutput struct {
	Body ChallengeIssuedPayload
}

// ValidateChallengeInput represents the input for validating a challenge
type ValidateChallengeInput struct {
	Authorization string `header:"Authorization" doc:"Session token" required:"false"`
	Token         string `query:"token" doc:"Challenge Token issued from signin or challenge requesting endpoint" required:"true"`
	Type          string `query:"type" doc:"Authenticator type: password, totp, webauthn, backup_code, pgp, ssh, or one a distribution adds" required:"true"`
	For           string `query:"for" doc:"The challenge target that you want to do for" enum:"passwordless,2fa,signin" required:"false"`
	Body          ChallengeResponsePayload
}

// ValidateChallengeOutput represents the output for validating a challenge
type ValidateChallengeOutput struct {
	Body ChallengeSuccessPayload
}
