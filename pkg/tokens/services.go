package tokens

import (
	"reflect"
	"sync"

	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// Services owns all token-related managers for a single Meiling app instance.
type Services struct {
	cfg config.MeilingConfig

	mu sync.RWMutex

	jwt               *JWTManager
	global            *GlobalTokenManager
	session           *SessionManager
	accessToken       *AccessTokenManager
	refreshToken      *RefreshTokenManager
	challenge         *ChallengeManager
	verification      *VerificationManager
	ownership         *OwnershipTokenManager
	registerToken     *ResourceRegisterTokenManager
	authorizationCode *AuthorizationCodeManager
	deviceCode        *DeviceCodeManager
}

func NewServices(cfg *config.MeilingConfig) *Services {
	if cfg == nil {
		panic("token configuration was not provided")
	}

	return &Services{
		cfg: cloneConfig(*cfg),
	}
}

// NewServicesFrom creates services for cfg that keep prev's global token store
// when the Valkey settings are unchanged, so tokens kept in memory survive a
// configuration reload.
func NewServicesFrom(cfg *config.MeilingConfig, prev *Services) *Services {
	s := NewServices(cfg)
	if prev != nil && reflect.DeepEqual(prev.cfg.ValkeyConfig, cfg.ValkeyConfig) {
		s.global = prev.Global()
	}
	return s
}

func (s *Services) Config() *config.MeilingConfig {
	return &s.cfg
}

func (s *Services) JWT() *JWTManager {
	return utils.LazyGet(&s.mu, &s.jwt, func() *JWTManager {
		return NewJWTManager(&s.cfg)
	})
}

func (s *Services) Global() *GlobalTokenManager {
	return utils.LazyGet(&s.mu, &s.global, func() *GlobalTokenManager {
		return NewGlobalTokenManager(&s.cfg)
	})
}

func (s *Services) Session() *SessionManager {
	return utils.LazyGet(&s.mu, &s.session, func() *SessionManager {
		return newSessionManager(s)
	})
}

func (s *Services) AccessToken() *AccessTokenManager {
	return utils.LazyGet(&s.mu, &s.accessToken, func() *AccessTokenManager {
		return newAccessTokenManager(s)
	})
}

func (s *Services) RefreshToken() *RefreshTokenManager {
	return utils.LazyGet(&s.mu, &s.refreshToken, func() *RefreshTokenManager {
		return newRefreshTokenManager(s)
	})
}

func (s *Services) Challenge() *ChallengeManager {
	return utils.LazyGet(&s.mu, &s.challenge, func() *ChallengeManager {
		return newChallengeManager(s)
	})
}

func (s *Services) Verification() *VerificationManager {
	return utils.LazyGet(&s.mu, &s.verification, func() *VerificationManager {
		return newVerificationManager(s)
	})
}

func (s *Services) Ownership() *OwnershipTokenManager {
	return utils.LazyGet(&s.mu, &s.ownership, func() *OwnershipTokenManager {
		return newOwnershipTokenManager(s)
	})
}

func (s *Services) RegisterToken() *ResourceRegisterTokenManager {
	return utils.LazyGet(&s.mu, &s.registerToken, func() *ResourceRegisterTokenManager {
		return newRegisterTokenManager(s)
	})
}

func (s *Services) AuthorizationCode() *AuthorizationCodeManager {
	return utils.LazyGet(&s.mu, &s.authorizationCode, func() *AuthorizationCodeManager {
		return newAuthorizationCodeManager(s)
	})
}

func (s *Services) DeviceCode() *DeviceCodeManager {
	return utils.LazyGet(&s.mu, &s.deviceCode, func() *DeviceCodeManager {
		return newDeviceCodeManager(s)
	})
}

func cloneConfig(cfg config.MeilingConfig) config.MeilingConfig {
	cfg.TokenConfig.JWT.AcceptingAlgorithms = append([]string(nil), cfg.TokenConfig.JWT.AcceptingAlgorithms...)
	cfg.TokenConfig.JWT.AcceptingIssuers = append([]string(nil), cfg.TokenConfig.JWT.AcceptingIssuers...)
	cfg.ValkeyConfig.InitAddress = append([]string(nil), cfg.ValkeyConfig.InitAddress...)
	return cfg
}
