package tokens

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/valkey-io/valkey-go"
)

var json = jsoniter.ConfigFastest

type TokenManager[T any] struct {
	services *Services
	Type     string
}

func (m *TokenManager[T]) getKey(id string) string {
	return m.Type + ":" + id
}

func (m *TokenManager[T]) ValidateType(token string) bool {
	jwt := m.services.JWT()

	claims, err := jwt.ParseTokenPrivateClaims(token)
	if err != nil {
		return false
	}

	if claims == nil {
		return false
	}

	if claims.TokenType != m.Type {
		return false
	}

	return true
}

func (m *TokenManager[T]) CreateIfNotExist(tid string, data T) error {
	if data, err := m.GetByTID(tid); err != nil {
		return nil
	} else {
		var t T

		if !reflect.DeepEqual(data, t) {
			return nil
		}
	}

	return m.SetByTID(tid, data)
}

func (m *TokenManager[T]) New(payload T) (uuid.UUID, string, error) {
	tid := uuid.New()
	data, err := m.NewWithTID(tid.String(), payload)
	return tid, data, err
}

func (m *TokenManager[T]) NewWithTID(tid string, payload T) (string, error) {
	jwtManager := m.services.JWT()

	claims := jwtManager.GetClaims()
	claims.ID = tid

	// if payload is a pointer, convert it to interface
	if reflect.ValueOf(payload).Kind() == reflect.Ptr {
		value := reflect.ValueOf(payload).Elem().Interface()
		var ok bool
		if payload, ok = value.(T); !ok {
			return "", fmt.Errorf("payload is not of expected type T")
		}
	}

	// Build private claims with token type, optional grant type and extra claims
	privateClaims := JWTGlobalPrivateClaims{
		TokenType: m.Type,
	}

	if reflect.ValueOf(payload).Kind() == reflect.Struct {
		// if it has Expiry field, set it from the payload.ExpiresAt
		valuePtr := reflect.ValueOf(&payload).Elem()
		expiresAt := valuePtr.FieldByName("ExpiresAt")

		if expiresAt.IsValid() {
			value := expiresAt.Interface()
			if value != nil {
				if v, ok := value.(time.Time); ok {
					if !v.IsZero() {
						claims.Expiry = jwt.NewNumericDate(v)
					}
				}
			}
		}

		// Extract GrantType if present
		grantType := valuePtr.FieldByName("GrantType")
		if grantType.IsValid() && grantType.Kind() == reflect.String {
			privateClaims.GrantType = grantType.String()
		}

		// Extract the claims a distribution added, if present
		if field := valuePtr.FieldByName("Claims"); field.IsValid() {
			if extra, ok := field.Interface().(map[string]any); ok {
				privateClaims.Extra = extra
			}
		}

		// Extract Audience if present
		audience := valuePtr.FieldByName("Audience")
		if audience.IsValid() && audience.Kind() == reflect.Slice {
			if aud, ok := audience.Interface().([]string); ok && len(aud) > 0 {
				claims.Audience = jwt.Audience(aud)
			}
		}

		// RFC 9068: for client_credentials access tokens, the client identifier is the subject.
		if claims.Subject == "" && m.Type == TokenTypeAccessToken && privateClaims.GrantType == "client_credentials" {
			clientID := valuePtr.FieldByName("ClientID")
			if clientID.IsValid() && clientID.Kind() == reflect.String {
				claims.Subject = clientID.String()
			}
		} else {
			// For user-bound tokens, set the JWT subject to the user identifier.
			userID := valuePtr.FieldByName("UserID")
			if userID.IsValid() && userID.Kind() == reflect.String && userID.String() != "" {
				claims.Subject = userID.String()
			}
		}

		// If Scope exists
		scope := valuePtr.FieldByName("Scope")
		if scope.IsValid() && scope.Kind() == reflect.String {
			privateClaims.Scope = scope.String()
		}
	}
	claims.NotBefore = jwt.NewNumericDate(time.Now())

	token, err := jwtManager.GenerateTokenWithPrivateClaims(claims, privateClaims)
	if err != nil {
		return "", err
	}

	err = m.SetByTID(tid, payload)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (m *TokenManager[T]) updateExpiresAt(payload T, claims *jwt.Claims) T {
	valuePtr := reflect.ValueOf(&payload).Elem()
	expiresAt := valuePtr.FieldByName("ExpiresAt")

	if expiresAt.IsValid() && expiresAt.CanSet() {
		if claims.Expiry != nil {
			expiresAt.Set(reflect.ValueOf(claims.Expiry.Time()))
		}
	}

	return payload
}

func (m *TokenManager[T]) Get(token string) (T, error) {
	var t T
	if !m.ValidateType(token) {
		return t, meilingErrors.New(meilingErrors.ErrTokenTypeMismatch, "invalid token type")
	}

	jwt := m.services.JWT()
	claims, err := jwt.ParseTokenClaims(token)
	if err != nil {
		return t, err
	}

	// check if claims is expired
	if claims.Expiry != nil {
		if claims.Expiry.Time().Before(time.Now()) {
			return t, meilingErrors.New(meilingErrors.ErrTokenExpired, "token expired")
		}
	}

	model, err := m.GetByTID(claims.ID)
	if err != nil {
		return t, err
	}

	model = m.updateExpiresAt(model, claims)
	return model, nil
}

func (m *TokenManager[T]) GetByTID(tid string) (T, error) {
	var t T
	key := m.getKey(tid)

	tokenManager := m.services.Global()
	result, err := tokenManager.Get(key, func(res valkey.ValkeyResult) (any, error) {
		var data T

		str, err := res.ToString()
		if err != nil {
			return nil, err
		}

		err = json.UnmarshalFromString(str, &data)
		if err != nil {
			return nil, err
		}

		return data, nil
	})

	if err != nil {
		if errors.Is(err, valkey.Nil) {
			return t, meilingErrors.New(meilingErrors.ErrUnidentifiedToken, "unidentified token")
		}
		return t, err
	}

	if v, ok := result.(T); ok {
		return v, nil
	}

	return t, meilingErrors.New(meilingErrors.ErrInvalidToken, "invalid token")
}

// consentLogIDIncludingRevoked returns the "consentLogId" field stored for the
// token, bypassing the revoked-token guard applied by Get/GetByTID. It is used
// for refresh-token reuse detection, where a revoked (rotated) token must still
// be traced back to its consent log so the whole lineage can be invalidated.
func (m *TokenManager[T]) consentLogIDIncludingRevoked(token string) (string, error) {
	jwtManager := m.services.JWT()
	claims, err := jwtManager.ParseTokenClaims(token)
	if err != nil {
		return "", err
	}

	key := m.getKey(claims.ID)
	data, err := m.services.Global().GetRawJSON(key)
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", meilingErrors.New(meilingErrors.ErrUnidentifiedToken, "unidentified token")
	}

	if v, ok := data["consentLogId"].(string); ok {
		return v, nil
	}

	return "", nil
}

func (m *TokenManager[T]) GetCustomClaims(token string, data any) error {
	value := reflect.ValueOf(data)
	if !value.IsValid() || value.Kind() != reflect.Ptr || value.IsNil() {
		return errors.New("Invalid data pointer")
	}

	jwtManager := m.services.JWT()
	return jwtManager.ParseTokenCustomClaims(token, data)
}

func (m *TokenManager[T]) Set(token string, data T) error {
	jwtManager := m.services.JWT()

	claims, err := jwtManager.ParseTokenClaims(token)
	if err != nil {
		return err
	}

	return m.SetByTID(claims.ID, data)
}

func (m *TokenManager[T]) SetByTID(tid string, data T) error {
	key := m.getKey(tid)
	tokenManager := m.services.Global()

	reflected := reflect.ValueOf(&data)

	reflectedStruct := reflected.Elem()
	if reflectedStruct.Kind() == reflect.Struct {
		// it has TID field. update it.
		field := reflectedStruct.FieldByName("TID")
		if field.IsValid() {
			field.SetString(tid)
		}
	}

	return tokenManager.Set(key, data)
}

func (m *TokenManager[T]) IsRevoked(token string) bool {
	jwt := m.services.JWT()

	claims, err := jwt.ParseTokenClaims(token)
	if err != nil {
		return true
	}

	return m.IsRevokedByTID(claims.ID)
}

func (m *TokenManager[T]) IsRevokedByTID(tid string) bool {
	key := m.getKey(tid)

	tokenManager := m.services.Global()
	return tokenManager.IsRevoked(key)
}

func (m *TokenManager[T]) Revoke(token string) error {
	jwt := m.services.JWT()

	claims, err := jwt.ParseTokenClaims(token)
	if err != nil {
		return err
	}

	return m.RevokeByTID(claims.ID)
}

// ClaimOnce reports whether this call is the first to redeem token.
func (m *TokenManager[T]) ClaimOnce(token string) (bool, error) {
	claims, err := m.services.JWT().ParseTokenClaims(token)
	if err != nil {
		return false, err
	}

	ttl := time.Hour
	if claims.Expiry != nil {
		ttl = max(time.Until(claims.Expiry.Time()), 0) + time.Minute
	}
	return m.services.Global().Claim(m.getKey(claims.ID), ttl)
}

func (m *TokenManager[T]) RevokeByTID(tid string) error {
	key := m.getKey(tid)

	tokenManager := m.services.Global()
	return tokenManager.Revoke(key)
}

func (m *TokenManager[T]) RevokedAt(token string) *time.Time {
	jwt := m.services.JWT()

	claims, err := jwt.ParseTokenClaims(token)
	if err != nil {
		return nil
	}

	return m.RevokedAtByTID(claims.ID)
}

func (m *TokenManager[T]) RevokedAtByTID(tid string) *time.Time {
	key := m.getKey(tid)

	tokenManager := m.services.Global()
	return tokenManager.RevokedAt(key)
}

func (m *TokenManager[T]) Delete(token string) error {
	jwt := m.services.JWT()

	claims, err := jwt.ParseTokenClaims(token)
	if err != nil {
		return err
	}

	return m.DeleteByTID(claims.ID)
}

func (m *TokenManager[T]) DeleteByTID(tid string) error {
	key := m.getKey(tid)

	tokenManager := m.services.Global()
	return tokenManager.Delete(key)
}

func (m *TokenManager[T]) IsExpired(token string) bool {
	jwt := m.services.JWT()

	claims, err := jwt.ParseTokenClaims(token)
	if err != nil {
		return true
	}

	if claims.Expiry.Time().Before(time.Now()) {
		return true
	}

	return false
}

func (m *TokenManager[T]) IsValid(token string) bool {
	return !m.IsRevoked(token) && !m.IsExpired(token)
}
