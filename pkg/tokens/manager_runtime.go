package tokens

import (
	"reflect"
	"time"

	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
)

type managedTokenManager[T any] struct {
	tokenManager TokenManager[T]
	expiresIn    time.Duration
}

func newManagedTokenManager[T any](services *Services, tokenType string, expiresIn time.Duration) managedTokenManager[T] {
	return managedTokenManager[T]{
		tokenManager: TokenManager[T]{
			services: services,
			Type:     tokenType,
		},
		expiresIn: expiresIn,
	}
}

func (m *managedTokenManager[T]) New(data T) (string, error) {
	if m.expiresIn > 0 {
		data = setTokenExpiresAt(data, time.Now().Add(m.expiresIn))
	}

	_, jwt, err := m.tokenManager.New(data)
	return jwt, err
}

func (m *managedTokenManager[T]) Get(token string) (T, error) {
	return m.tokenManager.Get(token)
}

func (m *managedTokenManager[T]) Set(token string, data T) error {
	return m.tokenManager.Set(token, data)
}

func (m *managedTokenManager[T]) Revoke(token string) error {
	if m.tokenManager.IsRevoked(token) {
		revokedAt := m.tokenManager.RevokedAt(token)
		if revokedAt != nil {
			return meilingErrors.New(meilingErrors.ErrTokenRevoked, "token has been revoked @ "+revokedAt.Format(time.RFC3339))
		}
		return meilingErrors.New(meilingErrors.ErrTokenRevoked, "token has been revoked")
	}

	return m.tokenManager.Revoke(token)
}

func (m *managedTokenManager[T]) IsRevoked(token string) bool {
	return m.tokenManager.IsRevoked(token)
}

func (m *managedTokenManager[T]) RevokedAt(token string) *time.Time {
	return m.tokenManager.RevokedAt(token)
}

func (m *managedTokenManager[T]) consentLogIDIncludingRevoked(token string) (string, error) {
	return m.tokenManager.consentLogIDIncludingRevoked(token)
}

func setTokenExpiresAt[T any](data T, expiresAt time.Time) T {
	value := reflect.ValueOf(&data).Elem()
	if value.Kind() != reflect.Struct {
		return data
	}

	field := value.FieldByName("ExpiresAt")
	if field.IsValid() && field.CanSet() && field.Type() == reflect.TypeOf(time.Time{}) {
		field.Set(reflect.ValueOf(expiresAt))
	}

	return data
}
