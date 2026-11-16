package tokens

import (
	"time"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func defaultTokenConfig() config.TokenConfig {
	cfg := config.TokenConfig{}
	_ = cfg.PostProcess()
	return cfg
}

func tokenConfig(services *Services) config.TokenConfig {
	if services != nil {
		if cfg := services.Config(); cfg != nil {
			return cfg.TokenConfig
		}
	}
	return defaultTokenConfig()
}

func tokenDuration(duration time.Duration, fallback time.Duration) time.Duration {
	if duration > 0 {
		return duration
	}
	return fallback
}
