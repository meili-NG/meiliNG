package tokens

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/valkey-io/valkey-go"
)

type GlobalTokenManager struct {
	mu sync.Mutex

	valkeyClient    valkey.Client
	valkeyAddresses []string

	valkeyUsername string
	valkeyPassword string
	valkeyTimeout  time.Duration

	fallbackStore sync.Map
}

type GlobalTokenPayload struct {
	TID       string    `json:"tid"`
	RevokedAt time.Time `json:"revokedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (m *GlobalTokenPayload) IsExpired() bool {
	return m.ExpiresAt.Before(time.Now())
}

func (m *GlobalTokenPayload) IsRevoked() bool {
	return !m.RevokedAt.IsZero() && m.RevokedAt.Before(time.Now())
}

func (m *GlobalTokenPayload) IsValid() bool {
	return !m.IsExpired() && !m.IsRevoked()
}

func (m *GlobalTokenPayload) IsNotBlank() bool {
	return m.TID != ""
}

const VALKEY_TTL = time.Second * 2
const defaultValkeyTimeout = time.Second * 5

func NewGlobalTokenManager(cfg *config.MeilingConfig) *GlobalTokenManager {
	manager := &GlobalTokenManager{}
	if cfg != nil && len(cfg.ValkeyConfig.InitAddress) > 0 {
		manager.valkeyAddresses = append([]string(nil), cfg.ValkeyConfig.InitAddress...)
		manager.valkeyUsername = cfg.ValkeyConfig.Username
		manager.valkeyPassword = cfg.ValkeyConfig.Password
		manager.valkeyTimeout = cfg.ValkeyConfig.Timeout
	}
	if manager.valkeyTimeout <= 0 {
		manager.valkeyTimeout = defaultValkeyTimeout
	}
	return manager
}

func (m *GlobalTokenManager) valkeyContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), m.valkeyTimeout)
}

func (m *GlobalTokenManager) getValkeyClient() (valkey.Client, error) {
	if m.IsValkeyEnabled() {
		if m.valkeyClient == nil {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.valkeyClient != nil {
				return m.valkeyClient, nil
			}

			option := valkey.ClientOption{
				InitAddress: m.valkeyAddresses,
			}

			if m.valkeyUsername != "" {
				option.Username = m.valkeyUsername
			}

			if m.valkeyPassword != "" {
				option.Password = m.valkeyPassword
			}

			client, err := valkey.NewClient(option)
			if err != nil {
				return nil, err
			}

			m.valkeyClient = client
		}

		return m.valkeyClient, nil
	}

	return nil, errors.New("valkey is not enabled")
}

func (m *GlobalTokenManager) IsValkeyEnabled() bool {
	return len(m.valkeyAddresses) > 0
}

func (m *GlobalTokenManager) CheckPayloadIsRevoked(data any) bool {
	if payload, ok := data.(GlobalTokenPayload); ok {
		if payload.RevokedAt.IsZero() {
			return false
		}
		return payload.RevokedAt.Before(time.Now())
	}

	// Check for embedded GlobalTokenPayload via reflection
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() == reflect.Struct {
		field := v.FieldByName("RevokedAt")
		if field.IsValid() && field.Type() == reflect.TypeOf(time.Time{}) {
			revokedAt := field.Interface().(time.Time)
			if revokedAt.IsZero() {
				return false
			}
			return revokedAt.Before(time.Now())
		}
	}

	return false
}

func (m *GlobalTokenManager) Get(id string, valkeyHandler func(res valkey.ValkeyResult) (any, error)) (any, error) {
	if m.IsValkeyEnabled() {
		client, err := m.getValkeyClient()
		if err != nil {
			return nil, err
		}

		ctx, cancel := m.valkeyContext()
		defer cancel()
		res := client.DoCache(ctx, client.B().Get().Key(id).Cache(), VALKEY_TTL)
		data, err := valkeyHandler(res)
		if err != nil {
			return nil, err
		}

		if m.CheckPayloadIsRevoked(data) {
			return nil, meilingErrors.New(meilingErrors.ErrTokenRevoked, "token is revoked")
		}

		return data, nil
	}

	if val, ok := m.fallbackStore.Load(id); ok {
		if m.CheckPayloadIsRevoked(val) {
			return nil, meilingErrors.New(meilingErrors.ErrTokenRevoked, "token is revoked")
		}

		return val, nil
	}

	return nil, nil
}

func (m *GlobalTokenManager) GetRawJSON(id string) (map[string]any, error) {
	if m.IsValkeyEnabled() {
		client, err := m.getValkeyClient()
		if err != nil {
			return nil, err
		}

		ctx, cancel := m.valkeyContext()
		defer cancel()
		res := client.DoCache(ctx, client.B().Get().Key(id).Cache(), VALKEY_TTL)

		var data map[string]any
		err = res.DecodeJSON(&data)

		if err != nil {
			return nil, err
		}

		return data, nil
	}

	if val, ok := m.fallbackStore.Load(id); ok {
		jsoned, err := json.Marshal(val)
		if err != nil {
			return nil, err
		}

		var data map[string]any
		err = json.Unmarshal(jsoned, &data)
		if err != nil {
			return nil, err
		}

		return data, nil
	}

	return nil, nil
}

func (m *GlobalTokenManager) Set(id string, value any) error {
	if v, ok := value.(GlobalTokenPayload); ok {
		if v.TID == "" {
			v.TID = id
		}
	}

	if m.IsValkeyEnabled() {
		client, err := m.getValkeyClient()
		if err != nil {
			return err
		}

		ctx, cancel := m.valkeyContext()
		defer cancel()

		marshalled, err := json.MarshalToString(value)
		if err != nil {
			return err
		}

		res := client.Do(ctx, client.B().Set().Key(id).Value(marshalled).Build())
		return res.Error()
	}

	m.fallbackStore.Store(id, value)
	return nil
}

func (m *GlobalTokenManager) RevokedAt(id string) *time.Time {
	if m.IsValkeyEnabled() {
		data, err := m.GetRawJSON(id)
		if err != nil {
			return nil
		}

		if data == nil {
			return nil
		}

		fieldName := "revokedAt"
		field, ok := reflect.TypeOf(GlobalTokenPayload{}).FieldByName("RevokedAt")
		if ok {
			fieldName = field.Tag.Get("json")
			fieldName = strings.Split(fieldName, ",")[0]
		}

		return rawJSONTime(data[fieldName])
	} else if val, ok := m.fallbackStore.Load(id); ok {
		if payload, ok := val.(GlobalTokenPayload); ok {
			if payload.RevokedAt.IsZero() {
				return nil
			} else {
				return &payload.RevokedAt
			}
		}
		// Handle types that embed GlobalTokenPayload
		v := reflect.ValueOf(val)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		if v.Kind() == reflect.Struct {
			field := v.FieldByName("RevokedAt")
			if field.IsValid() && field.Type() == reflect.TypeOf(time.Time{}) {
				revokedAt := field.Interface().(time.Time)
				if revokedAt.IsZero() {
					return nil
				}
				return &revokedAt
			}
		}
	}
	return nil
}

// rawJSONTime reads a timestamp from a record decoded into map[string]any,
// where payload structs marshal time.Time as an RFC 3339 string. The zero
// time means "not set" and returns nil.
func rawJSONTime(value any) *time.Time {
	v, ok := value.(string)
	if !ok {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil || t.IsZero() {
		return nil
	}
	return &t
}

// Claim marks id as used and reports whether this call was the first to do so.
// The check and the mark are one atomic step, so concurrent callers cannot both win.
func (m *GlobalTokenManager) Claim(id string, ttl time.Duration) (bool, error) {
	key := id + ":claimed"
	if m.IsValkeyEnabled() {
		client, err := m.getValkeyClient()
		if err != nil {
			return false, err
		}

		ctx, cancel := m.valkeyContext()
		defer cancel()

		err = client.Do(ctx, client.B().Set().Key(key).Value("1").Nx().Ex(ttl).Build()).Error()
		if errors.Is(err, valkey.Nil) {
			return false, nil
		}
		return err == nil, err
	}

	_, loaded := m.fallbackStore.LoadOrStore(key, true)
	return !loaded, nil
}

func (m *GlobalTokenManager) Revoke(id string) error {
	if m.IsValkeyEnabled() {
		data, err := m.GetRawJSON(id)
		if err != nil {
			return err
		}

		if data == nil {
			return nil
		}

		fieldName := "revokedAt"
		field, ok := reflect.TypeOf(GlobalTokenPayload{}).FieldByName("RevokedAt")
		if ok {
			fieldName = field.Tag.Get("json")
			fieldName = strings.Split(fieldName, ",")[0]
		}

		// Write the same RFC 3339 form the payload struct marshals to, so the
		// record still decodes into its typed payload after revocation.
		data[fieldName] = time.Now()
		return m.Set(id, data)
	} else if val, ok := m.fallbackStore.Load(id); ok {
		if payload, ok := val.(GlobalTokenPayload); ok {
			payload.RevokedAt = time.Now()
			m.fallbackStore.Store(id, payload)
		} else {
			// Handle types that embed GlobalTokenPayload
			v := reflect.ValueOf(val)
			if v.Kind() == reflect.Struct {
				// Make a settable copy
				cp := reflect.New(v.Type()).Elem()
				cp.Set(v)
				field := cp.FieldByName("RevokedAt")
				if field.IsValid() && field.CanSet() && field.Type() == reflect.TypeOf(time.Time{}) {
					field.Set(reflect.ValueOf(time.Now()))
					m.fallbackStore.Store(id, cp.Interface())
				}
			}
		}
	}
	return nil
}

func (m *GlobalTokenManager) ExpiresAt(id string) *time.Time {
	if m.IsValkeyEnabled() {
		data, err := m.GetRawJSON(id)
		if err != nil {
			return nil
		}

		if data == nil {
			return nil
		}

		fieldName := "expiresAt"
		field, ok := reflect.TypeOf(GlobalTokenPayload{}).FieldByName("ExpiresAt")
		if ok {
			fieldName = field.Tag.Get("json")
			fieldName = strings.Split(fieldName, ",")[0]
		}

		return rawJSONTime(data[fieldName])
	} else if val, ok := m.fallbackStore.Load(id); ok {
		if payload, ok := val.(GlobalTokenPayload); ok {
			if payload.ExpiresAt.IsZero() {
				return nil
			} else {
				return &payload.ExpiresAt
			}
		}
	}
	return nil
}

// AcquireSharedString atomically elects a shared string value across the
// cluster: it attempts SET key value NX EX ttl, then GETs the key so every
// caller converges on whichever value won the race. Used to agree on a single
// magic admin token across replicas. Requires Valkey; returns an error when it
// is disabled so callers can fall back to per-process behavior.
func (m *GlobalTokenManager) AcquireSharedString(key, value string, ttl time.Duration) (string, error) {
	client, err := m.getValkeyClient()
	if err != nil {
		return "", err
	}

	ctx, cancel := m.valkeyContext()
	defer cancel()

	// NX makes this a no-op if another replica already elected a value; we then
	// read back the winning value below.
	seconds := int64(ttl.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	setCmd := client.B().Set().Key(key).Value(value).Nx().ExSeconds(seconds).Build()
	if err := client.Do(ctx, setCmd).Error(); err != nil {
		// A nil reply (key already set) surfaces as an error in valkey-go; fall
		// through to GET regardless so we return the elected value.
		if !valkey.IsValkeyNil(err) {
			return "", err
		}
	}

	got, err := client.Do(ctx, client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		return "", err
	}
	return got, nil
}

// GetSharedString reads a plain string key. A missing key returns ("", nil).
func (m *GlobalTokenManager) GetSharedString(key string) (string, error) {
	client, err := m.getValkeyClient()
	if err != nil {
		return "", err
	}

	ctx, cancel := m.valkeyContext()
	defer cancel()
	got, err := client.Do(ctx, client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return "", nil
		}
		return "", err
	}
	return got, nil
}

// DeleteSharedKey removes a shared key across the cluster.
func (m *GlobalTokenManager) DeleteSharedKey(key string) error {
	return m.Delete(key)
}

func (m *GlobalTokenManager) Delete(id string) error {
	if m.IsValkeyEnabled() {
		client, err := m.getValkeyClient()
		if err != nil {
			return err
		}

		ctx, cancel := m.valkeyContext()
		defer cancel()
		res := client.Do(ctx, client.B().Del().Key(id).Build())
		return res.Error()
	}

	m.fallbackStore.Delete(id)
	return nil
}

func (m *GlobalTokenManager) IsRevoked(id string) bool {
	revokedAt := m.RevokedAt(id)

	if revokedAt == nil {
		return false
	} else {
		return revokedAt.Before(time.Now())
	}
}

func (m *GlobalTokenManager) IsExpired(id string) bool {
	expiresAt := m.ExpiresAt(id)

	if expiresAt == nil {
		return false
	} else {
		return expiresAt.Before(time.Now())
	}
}

func (m *GlobalTokenManager) IsValid(id string) bool {
	return !m.IsRevoked(id) && !m.IsExpired(id)
}
