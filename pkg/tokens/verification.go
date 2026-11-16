package tokens

import (
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
)

type VerificationServerPayload struct {
	GlobalTokenPayload

	Challenge string `json:"challenge"`
}

type VerificationManager struct {
	tokenManager TokenManager[VerificationServerPayload]
}

type VerificationPayload struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type VerificationMergedPayload struct {
	VerificationPayload
	VerificationServerPayload
}

const TokenTypeVerification = "verification"

func newVerificationManager(services *Services) *VerificationManager {
	return &VerificationManager{
		tokenManager: TokenManager[VerificationServerPayload]{
			services: services,
			Type:     TokenTypeVerification,
		},
	}
}

func (m *VerificationManager) New(payload VerificationMergedPayload) (string, error) {
	_, token, err := m.tokenManager.New(payload.VerificationServerPayload)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (m *VerificationManager) Get(token string) (*VerificationMergedPayload, error) {
	payload := VerificationMergedPayload{}
	err := m.tokenManager.GetCustomClaims(token, &payload)
	if err != nil {
		return nil, err
	}

	serverPayload, err := m.tokenManager.Get(token)
	if err != nil {
		return nil, err
	}

	payload.VerificationServerPayload = serverPayload
	return &payload, nil
}

func (m *VerificationManager) GetAndMerge(tokens []string) (*VerificationMergedPayload, error) {
	payload := VerificationMergedPayload{}

	for _, token := range tokens {
		data, err := m.Get(token)
		if err != nil {
			return nil, err
		}

		if data.Email != "" {
			payload.Email = data.Email
		}

		if data.Phone != "" {
			payload.Phone = data.Phone
		}
	}

	return &payload, nil
}

func (m *VerificationManager) Use(token string) (*VerificationMergedPayload, error) {
	if m.IsRevoked(token) {
		return nil, meilingErrors.New(meilingErrors.ErrTokenRevoked, "token has been revoked")
	}

	data, err := m.Get(token)
	if err != nil {
		return nil, err
	}

	err = m.Revoke(token)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (m *VerificationManager) Revoke(token string) error {
	err := m.tokenManager.Set(token, VerificationServerPayload{})
	if err != nil {
		return err
	}

	return m.tokenManager.Revoke(token)
}

func (m *VerificationManager) IsRevoked(token string) bool {
	return m.tokenManager.IsRevoked(token)
}
