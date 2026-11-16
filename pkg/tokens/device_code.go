package tokens

import (
	"errors"
	"strings"
	"time"

	"github.com/meili-NG/meiliNG/v2/internal/utils"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/valkey-io/valkey-go"
)

const (
	TokenTypeDeviceCode = "oauth2_device_code"

	DeviceCodeStatusPending    = "pending"
	DeviceCodeStatusAuthorized = "authorized"
	DeviceCodeStatusDenied     = "denied"
)

type DeviceCodeContent struct {
	GlobalTokenPayload

	UserCode     string    `json:"userCode"`
	UserID       string    `json:"userId,omitempty"`
	ClientID     string    `json:"clientId"`
	Permissions  []string  `json:"permissions,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	Status       string    `json:"status"`
	ConsentLogID string    `json:"consentLogId,omitempty"`
	AccessType   string    `json:"accessType"`
	PollInterval int       `json:"pollInterval"`
	LastPolledAt time.Time `json:"lastPolledAt"`
}

func (c DeviceCodeContent) IsClient(clientID string) bool {
	return c.ClientID == clientID
}

func (c DeviceCodeContent) IsPending() bool {
	return c.Status == "" || c.Status == DeviceCodeStatusPending
}

func (c DeviceCodeContent) IsAuthorized() bool {
	return c.Status == DeviceCodeStatusAuthorized
}

func (c DeviceCodeContent) IsDenied() bool {
	return c.Status == DeviceCodeStatusDenied
}

type DeviceUserCodeContent struct {
	GlobalTokenPayload

	DeviceCode string `json:"deviceCode"`
	UserCode   string `json:"userCode"`
}

type DeviceCodeManager struct {
	services  *Services
	expiresIn time.Duration
}

func newDeviceCodeManager(services *Services) *DeviceCodeManager {
	cfg := tokenConfig(services)
	return &DeviceCodeManager{
		services:  services,
		expiresIn: tokenDuration(cfg.DeviceCode.Duration, defaultTokenConfig().DeviceCode.Duration),
	}
}

func (m *DeviceCodeManager) New(data DeviceCodeContent) (string, error) {
	if m.expiresIn > 0 {
		data.ExpiresAt = time.Now().Add(m.expiresIn)
	}
	if data.Status == "" {
		data.Status = DeviceCodeStatusPending
	}
	if data.PollInterval <= 0 {
		data.PollInterval = 5
	}

	for range 5 {
		deviceCode := GenerateDeviceCode()
		if _, err := m.getDeviceCode(deviceCode); err == nil {
			continue
		}
		if err := m.setDeviceCode(deviceCode, data); err != nil {
			return "", err
		}
		if err := m.setUserCode(data.UserCode, deviceCode, data.ExpiresAt); err != nil {
			return "", err
		}
		return deviceCode, nil
	}

	return "", errors.New("device code issuance failed")
}

func (m *DeviceCodeManager) GetExpirationInSeconds() int {
	return int(m.expiresIn.Seconds())
}

func (m *DeviceCodeManager) Get(token string) (DeviceCodeContent, error) {
	return m.getDeviceCode(token)
}

func (m *DeviceCodeManager) Set(token string, data DeviceCodeContent) error {
	return m.setDeviceCode(token, data)
}

func (m *DeviceCodeManager) Revoke(token string) error {
	data, err := m.getDeviceCode(token)
	if err != nil {
		return err
	}
	data.RevokedAt = time.Now()
	return m.setDeviceCode(token, data)
}

func (m *DeviceCodeManager) IsRevoked(token string) bool {
	data, err := m.getDeviceCode(token)
	if err != nil {
		return false
	}
	return data.IsRevoked()
}

func (m *DeviceCodeManager) GetByUserCode(userCode string) (DeviceCodeContent, string, error) {
	mapping, err := m.getUserCode(userCode)
	if err != nil {
		return DeviceCodeContent{}, "", err
	}

	data, err := m.Get(mapping.DeviceCode)
	if err != nil {
		return DeviceCodeContent{}, "", err
	}

	return data, mapping.DeviceCode, nil
}

func (m *DeviceCodeManager) DeleteUserCode(userCode string) error {
	return m.services.Global().Delete(m.userCodeKey(userCode))
}

func GenerateDeviceCode() string {
	return utils.RandomStringWithCharset(64, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_~")
}

func GenerateDeviceUserCode() string {
	raw := utils.RandomStringWithCharset(8, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
	return raw[:4] + "-" + raw[4:]
}

func NormalizeDeviceUserCode(userCode string) string {
	normalized := strings.ToUpper(strings.TrimSpace(userCode))
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	if len(normalized) == 8 {
		return normalized[:4] + "-" + normalized[4:]
	}
	return normalized
}

func (m *DeviceCodeManager) userCodeKey(userCode string) string {
	return TokenTypeDeviceCode + ":user_code:" + NormalizeDeviceUserCode(userCode)
}

func (m *DeviceCodeManager) deviceCodeKey(deviceCode string) string {
	return TokenTypeDeviceCode + ":device_code:" + deviceCode
}

func (m *DeviceCodeManager) setDeviceCode(deviceCode string, data DeviceCodeContent) error {
	return m.services.Global().Set(m.deviceCodeKey(deviceCode), data)
}

func (m *DeviceCodeManager) getDeviceCode(deviceCode string) (DeviceCodeContent, error) {
	var t DeviceCodeContent
	result, err := m.services.Global().Get(m.deviceCodeKey(deviceCode), func(res valkey.ValkeyResult) (any, error) {
		var data DeviceCodeContent
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
		return t, err
	}

	data, ok := result.(DeviceCodeContent)
	if !ok || data.ClientID == "" {
		return t, meilingErrors.New(meilingErrors.ErrUnidentifiedToken, "unidentified device code")
	}
	if data.IsExpired() {
		return t, meilingErrors.New(meilingErrors.ErrTokenExpired, "device code expired")
	}
	if data.IsRevoked() {
		return t, meilingErrors.New(meilingErrors.ErrTokenRevoked, "device code revoked")
	}

	return data, nil
}

func (m *DeviceCodeManager) setUserCode(userCode string, deviceCode string, expiresAt time.Time) error {
	return m.services.Global().Set(m.userCodeKey(userCode), DeviceUserCodeContent{
		GlobalTokenPayload: GlobalTokenPayload{
			ExpiresAt: expiresAt,
		},
		DeviceCode: deviceCode,
		UserCode:   NormalizeDeviceUserCode(userCode),
	})
}

func (m *DeviceCodeManager) getUserCode(userCode string) (DeviceUserCodeContent, error) {
	var t DeviceUserCodeContent
	result, err := m.services.Global().Get(m.userCodeKey(userCode), func(res valkey.ValkeyResult) (any, error) {
		var data DeviceUserCodeContent
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
		return t, err
	}

	data, ok := result.(DeviceUserCodeContent)
	if !ok || data.DeviceCode == "" {
		return t, meilingErrors.New(meilingErrors.ErrUnidentifiedToken, "unidentified user code")
	}
	if data.IsExpired() {
		return t, meilingErrors.New(meilingErrors.ErrTokenExpired, "user code expired")
	}

	return data, nil
}
