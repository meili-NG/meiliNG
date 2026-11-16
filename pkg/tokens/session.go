package tokens

import (
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/valkey-io/valkey-go"
)

type SessionPayload struct {
	GlobalTokenPayload
	SID   string   `json:"sid"`
	Users []string `json:"users"`
	// Auth records how each user in Users last signed in, keyed by user ID.
	Auth map[string]UserAuth `json:"auth,omitempty"`
}

// UserAuth is how a user signed into a session.
type UserAuth struct {
	// Time is when, in Unix seconds.
	Time int64 `json:"time"`
	// Methods are the authenticator types passed.
	Methods []string `json:"methods"`
	// TwoFactor is whether a second factor, or a passwordless authenticator,
	// was passed.
	TwoFactor bool `json:"twoFactor"`
}

type JWTSessionPrivateClaims struct {
	SID string `json:"sid,omitempty"`
}

type sessionState struct {
	SID       string              `json:"sid"`
	ActiveTID string              `json:"activeTid"`
	Users     []string            `json:"users"`
	Auth      map[string]UserAuth `json:"auth,omitempty"`
	RevokedAt time.Time           `json:"revokedAt"`
	ExpiresAt time.Time           `json:"expiresAt"`
}

type sessionTokenRecord struct {
	TID       string    `json:"tid"`
	SID       string    `json:"sid"`
	ExpiresAt time.Time `json:"expiresAt"`
	RevokedAt time.Time `json:"revokedAt"`
}

type parsedSessionToken struct {
	TID       string
	SID       string
	ExpiresAt time.Time
}

type SessionManager struct {
	services *Services
}

const TokenTypeSession = "session"

func newSessionManager(services *Services) *SessionManager {
	return &SessionManager{services: services}
}

func (m *SessionManager) sidKey(sid string) string {
	return "session:sid:" + sid
}

func (m *SessionManager) tidKey(tid string) string {
	return "session:tid:" + tid
}

func (m *SessionManager) GeneratePayload() SessionPayload {
	data := SessionPayload{
		Users: []string{},
	}

	data.ExpiresAt = time.Now().Add(m.sessionDuration())
	return data
}

func (m *SessionManager) Create() (uuid.UUID, string, error) {
	sid := uuid.New()
	tid := uuid.New()

	payload := m.GeneratePayload()
	payload.SID = sid.String()
	payload.TID = tid.String()

	token, err := m.issueToken(payload)
	if err != nil {
		return uuid.UUID{}, "", err
	}

	if err := m.storePayload(payload); err != nil {
		return uuid.UUID{}, "", err
	}

	return tid, token, nil
}

func (m *SessionManager) Renew(token string) (SessionPayload, string, error) {
	payload, err := m.Get(token)
	if err != nil {
		return payload, "", err
	}
	if !payload.IsNotBlank() {
		return payload, "", meilingErrors.New(meilingErrors.ErrUnidentifiedToken, "unidentified token")
	}
	if !payload.IsValid(m) {
		return payload, "", meilingErrors.New(meilingErrors.ErrTokenExpired, "token expired")
	}

	if !m.CanRenew(payload) {
		return payload, "", meilingErrors.New(meilingErrors.ErrInvalidRequest, "session renewal is not available yet")
	}

	renewalBase := time.Now()
	if payload.ExpiresAt.After(renewalBase) {
		renewalBase = payload.ExpiresAt
	}
	payload.ExpiresAt = renewalBase.Add(m.sessionDuration())

	oldTID := payload.TID
	payload.TID = uuid.NewString()

	renewedToken, err := m.issueToken(payload)
	if err != nil {
		return payload, "", err
	}

	record := sessionTokenRecord{
		TID:       payload.TID,
		SID:       payload.SID,
		ExpiresAt: payload.ExpiresAt,
	}
	if err := m.storeTokenRecord(record); err != nil {
		return payload, "", err
	}

	if err := m.storeSessionState(sessionState{
		SID:       payload.SID,
		ActiveTID: payload.TID,
		Users:     append([]string(nil), payload.Users...),
		Auth:      payload.Auth,
		RevokedAt: payload.RevokedAt,
		ExpiresAt: payload.ExpiresAt,
	}); err != nil {
		return payload, "", err
	}

	if err := m.deleteTokenRecord(oldTID); err != nil {
		return payload, "", err
	}

	return payload, renewedToken, nil
}

func (m *SessionManager) CanRenew(payload SessionPayload) bool {
	if !payload.IsNotBlank() || payload.ExpiresAt.IsZero() {
		return false
	}

	return time.Until(payload.ExpiresAt) <= m.sessionRenewalThreshold()
}

func (m *SessionManager) RenewableAfter(payload SessionPayload) time.Time {
	if payload.ExpiresAt.IsZero() {
		return time.Time{}
	}

	return payload.ExpiresAt.Add(-m.sessionRenewalThreshold())
}

func (m *SessionManager) sessionDuration() time.Duration {
	cfg := tokenConfig(m.services)
	return tokenDuration(cfg.Session.Duration, defaultTokenConfig().Session.Duration)
}

func (m *SessionManager) sessionRenewalThreshold() time.Duration {
	cfg := tokenConfig(m.services)
	return tokenDuration(cfg.Session.RenewalThreshold, defaultTokenConfig().Session.RenewalThreshold)
}

func (m *SessionManager) issueToken(payload SessionPayload) (string, error) {
	jwtManager := m.services.JWT()
	baseClaims := jwtManager.GetClaims()
	baseClaims.ID = payload.TID
	if !payload.ExpiresAt.IsZero() {
		baseClaims.Expiry = jwt.NewNumericDate(payload.ExpiresAt)
	}

	claims := struct {
		ExtendedJWTClaims
		SID string `json:"sid,omitempty"`
	}{
		ExtendedJWTClaims: *baseClaims,
		SID:               payload.SID,
	}

	return jwtManager.GenerateTokenFromCustomClaimsWithPrivateClaims(claims, JWTGlobalPrivateClaims{
		TokenType: TokenTypeSession,
	})
}

func (m *SessionManager) parseToken(token string) (parsedSessionToken, error) {
	var parsed parsedSessionToken

	jwtManager := m.services.JWT()
	privateClaims, err := jwtManager.ParseTokenPrivateClaims(token)
	if err != nil {
		return parsed, err
	}
	if privateClaims.TokenType != TokenTypeSession {
		return parsed, meilingErrors.New(meilingErrors.ErrTokenTypeMismatch, "invalid token type")
	}

	claims, err := jwtManager.ParseTokenClaims(token)
	if err != nil {
		return parsed, err
	}
	if claims.Expiry != nil && claims.Expiry.Time().Before(time.Now()) {
		return parsed, meilingErrors.New(meilingErrors.ErrTokenExpired, "token expired")
	}

	var sessionClaims JWTSessionPrivateClaims
	if err := jwtManager.ParseTokenCustomClaims(token, &sessionClaims); err != nil {
		return parsed, err
	}
	if claims.ID == "" || sessionClaims.SID == "" {
		return parsed, meilingErrors.New(meilingErrors.ErrInvalidToken, "invalid session token")
	}

	parsed.TID = claims.ID
	parsed.SID = sessionClaims.SID
	if claims.Expiry != nil {
		parsed.ExpiresAt = claims.Expiry.Time()
	}

	return parsed, nil
}

func (m *SessionManager) payloadFromState(state sessionState, tid string, expiresAt time.Time) SessionPayload {
	payload := SessionPayload{
		SID:   state.SID,
		Users: append([]string(nil), state.Users...),
		Auth:  state.Auth,
		GlobalTokenPayload: GlobalTokenPayload{
			TID:       tid,
			RevokedAt: state.RevokedAt,
			ExpiresAt: state.ExpiresAt,
		},
	}
	if !expiresAt.IsZero() {
		payload.ExpiresAt = expiresAt
	}
	return payload
}

func (m *SessionManager) storePayload(payload SessionPayload) error {
	if payload.SID == "" || payload.TID == "" {
		return meilingErrors.New(meilingErrors.ErrInvalidRequest, "session sid and tid are required")
	}

	state := sessionState{
		SID:       payload.SID,
		ActiveTID: payload.TID,
		Users:     append([]string(nil), payload.Users...),
		Auth:      payload.Auth,
		RevokedAt: payload.RevokedAt,
		ExpiresAt: payload.ExpiresAt,
	}
	record := sessionTokenRecord{
		TID:       payload.TID,
		SID:       payload.SID,
		ExpiresAt: payload.ExpiresAt,
		RevokedAt: payload.RevokedAt,
	}

	if err := m.storeTokenRecord(record); err != nil {
		return err
	}

	return m.storeSessionState(state)
}

func (m *SessionManager) storeSessionState(state sessionState) error {
	return m.services.Global().Set(m.sidKey(state.SID), state)
}

func (m *SessionManager) storeTokenRecord(record sessionTokenRecord) error {
	return m.services.Global().Set(m.tidKey(record.TID), record)
}

func (m *SessionManager) deleteTokenRecord(tid string) error {
	if tid == "" {
		return nil
	}
	return m.services.Global().Delete(m.tidKey(tid))
}

func (m *SessionManager) loadSessionState(sid string) (sessionState, error) {
	return m.loadSessionStateByKey(m.sidKey(sid))
}

func (m *SessionManager) loadSessionStateByKey(key string) (sessionState, error) {
	var state sessionState

	result, err := m.services.Global().Get(key, func(res valkey.ValkeyResult) (any, error) {
		var data sessionState
		str, err := res.ToString()
		if err != nil {
			return nil, err
		}
		if err := json.UnmarshalFromString(str, &data); err != nil {
			return nil, err
		}
		return data, nil
	})
	if err != nil {
		if errors.Is(err, valkey.Nil) {
			return state, meilingErrors.New(meilingErrors.ErrUnidentifiedToken, "unidentified token")
		}
		return state, err
	}
	if result == nil {
		return state, meilingErrors.New(meilingErrors.ErrUnidentifiedToken, "unidentified token")
	}
	if data, ok := result.(sessionState); ok {
		return data, nil
	}
	return state, meilingErrors.New(meilingErrors.ErrInvalidToken, "invalid token")
}

func (m *SessionManager) loadTokenRecord(tid string) (sessionTokenRecord, error) {
	var record sessionTokenRecord

	result, err := m.services.Global().Get(m.tidKey(tid), func(res valkey.ValkeyResult) (any, error) {
		var data sessionTokenRecord
		str, err := res.ToString()
		if err != nil {
			return nil, err
		}
		if err := json.UnmarshalFromString(str, &data); err != nil {
			return nil, err
		}
		return data, nil
	})
	if err != nil {
		if errors.Is(err, valkey.Nil) {
			return record, meilingErrors.New(meilingErrors.ErrUnidentifiedToken, "unidentified token")
		}
		return record, err
	}
	if result == nil {
		return record, meilingErrors.New(meilingErrors.ErrUnidentifiedToken, "unidentified token")
	}
	if data, ok := result.(sessionTokenRecord); ok {
		return data, nil
	}
	return record, meilingErrors.New(meilingErrors.ErrInvalidToken, "invalid token")
}

func (m *SessionManager) Get(token string) (SessionPayload, error) {
	var payload SessionPayload

	parsed, err := m.parseToken(token)
	if err != nil {
		return payload, err
	}

	record, err := m.loadTokenRecord(parsed.TID)
	if err != nil {
		return payload, err
	}
	if record.SID != parsed.SID {
		return payload, meilingErrors.New(meilingErrors.ErrInvalidToken, "invalid session token")
	}

	state, err := m.loadSessionState(parsed.SID)
	if err != nil {
		return payload, err
	}
	if state.ActiveTID != parsed.TID {
		return payload, meilingErrors.New(meilingErrors.ErrTokenRevoked, "token is revoked")
	}

	payload = m.payloadFromState(state, parsed.TID, record.ExpiresAt)
	return payload, nil
}

func (m *SessionManager) GetBySID(sid string) (SessionPayload, error) {
	var payload SessionPayload

	state, err := m.loadSessionState(sid)
	if err != nil {
		return payload, err
	}
	if state.ActiveTID == "" {
		return payload, meilingErrors.New(meilingErrors.ErrUnidentifiedToken, "unidentified token")
	}

	record, err := m.loadTokenRecord(state.ActiveTID)
	if err != nil {
		return payload, err
	}

	return m.payloadFromState(state, state.ActiveTID, record.ExpiresAt), nil
}

func (m *SessionManager) GetByTID(tid string) (SessionPayload, error) {
	var payload SessionPayload

	record, err := m.loadTokenRecord(tid)
	if err != nil {
		return payload, err
	}

	state, err := m.loadSessionState(record.SID)
	if err != nil {
		return payload, err
	}
	if state.ActiveTID != tid {
		return payload, meilingErrors.New(meilingErrors.ErrTokenRevoked, "token is revoked")
	}

	return m.payloadFromState(state, tid, record.ExpiresAt), nil
}

func (m *SessionManager) GetOrCreate(id string) (SessionPayload, error) {
	payload, err := m.GetBySID(id)
	if err == nil && payload.IsNotBlank() {
		return payload, nil
	}

	newPayload := m.GeneratePayload()
	newPayload.SID = id
	newPayload.TID = uuid.NewString()

	if err := m.storePayload(newPayload); err != nil {
		return SessionPayload{}, err
	}

	return newPayload, nil
}

func (m *SessionManager) Set(token string, data SessionPayload) error {
	parsed, err := m.parseToken(token)
	if err != nil {
		return err
	}
	if _, err := m.Get(token); err != nil {
		return err
	}
	data.SID = parsed.SID
	data.TID = parsed.TID
	return m.SetBySID(parsed.SID, data)
}

func (m *SessionManager) SetBySID(sid string, data SessionPayload) error {
	state, err := m.loadSessionState(sid)
	if err != nil {
		return err
	}

	if data.ExpiresAt.IsZero() {
		data.ExpiresAt = state.ExpiresAt
	}

	state.Users = append([]string(nil), data.Users...)
	state.Auth = data.Auth
	state.RevokedAt = data.RevokedAt
	state.ExpiresAt = data.ExpiresAt

	if err := m.storeSessionState(state); err != nil {
		return err
	}

	record, err := m.loadTokenRecord(state.ActiveTID)
	if err != nil {
		return err
	}
	record.ExpiresAt = data.ExpiresAt
	record.RevokedAt = data.RevokedAt
	return m.storeTokenRecord(record)
}

func (m *SessionManager) SetByTID(tid string, data SessionPayload) error {
	record, err := m.loadTokenRecord(tid)
	if err != nil {
		return err
	}

	data.SID = record.SID
	data.TID = tid
	return m.SetBySID(record.SID, data)
}

func (m *SessionManager) deleteBySID(sid string) error {
	state, err := m.loadSessionState(sid)
	if err != nil {
		var merr *meilingErrors.Error
		if errors.As(err, &merr) && merr.Type == meilingErrors.ErrUnidentifiedToken {
			return nil
		}
		return err
	}

	if err := m.deleteTokenRecord(state.ActiveTID); err != nil {
		return err
	}
	return m.services.Global().Delete(m.sidKey(sid))
}

func (m *SessionManager) Revoke(token string) error {
	parsed, err := m.parseToken(token)
	if err != nil {
		return err
	}
	return m.deleteBySID(parsed.SID)
}

func (m *SessionManager) RevokeBySID(sid string) error {
	return m.deleteBySID(sid)
}

func (m *SessionManager) RevokeByTID(tid string) error {
	record, err := m.loadTokenRecord(tid)
	if err != nil {
		return err
	}
	return m.deleteBySID(record.SID)
}

func (m *SessionManager) IsRevokedBySID(sid string) bool {
	return m.services.Global().IsRevoked(m.sidKey(sid))
}

func (m *SessionManager) IsRevokedByTID(tid string) bool {
	record, err := m.loadTokenRecord(tid)
	if err != nil {
		return true
	}

	state, err := m.loadSessionState(record.SID)
	if err != nil {
		return true
	}

	return state.ActiveTID != tid || (!state.RevokedAt.IsZero() && state.RevokedAt.Before(time.Now()))
}

func (m *SessionManager) IsRevoked(token string) bool {
	parsed, err := m.parseToken(token)
	if err != nil {
		return true
	}

	record, err := m.loadTokenRecord(parsed.TID)
	if err != nil {
		return true
	}

	state, err := m.loadSessionState(parsed.SID)
	if err != nil {
		return true
	}

	return record.SID != parsed.SID || state.ActiveTID != parsed.TID || state.RevokedAt.Before(time.Now()) && !state.RevokedAt.IsZero()
}

func (m *SessionManager) Delete(token string) error {
	parsed, err := m.parseToken(token)
	if err != nil {
		return err
	}
	return m.deleteBySID(parsed.SID)
}

func (m *SessionManager) DeleteBySID(sid string) error {
	return m.deleteBySID(sid)
}

func (m *SessionManager) DeleteByTID(tid string) error {
	record, err := m.loadTokenRecord(tid)
	if err != nil {
		return err
	}
	return m.deleteBySID(record.SID)
}

func (m *SessionManager) IsExpired(token string) bool {
	parsed, err := m.parseToken(token)
	if err != nil {
		return true
	}
	if !parsed.ExpiresAt.IsZero() && parsed.ExpiresAt.Before(time.Now()) {
		return true
	}

	state, err := m.loadSessionState(parsed.SID)
	if err != nil {
		return true
	}

	return !state.ExpiresAt.IsZero() && state.ExpiresAt.Before(time.Now())
}

func (m *SessionManager) IsValid(token string) bool {
	return !m.IsRevoked(token) && !m.IsExpired(token)
}
