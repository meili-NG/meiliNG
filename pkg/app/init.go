package app

import (
	"context"
	"fmt"

	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"github.com/meili-NG/meiliNG/v2/internal/validator"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/auth"
	"github.com/meili-NG/meiliNG/v2/pkg/avatar"
	"github.com/meili-NG/meiliNG/v2/pkg/captcha"
	"github.com/meili-NG/meiliNG/v2/pkg/common"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
	"github.com/meili-NG/meiliNG/v2/pkg/geoip"
	// Enable the built-in notification providers. Other providers register
	// themselves from their own imports, so this line never changes as
	// providers are added.
	_ "github.com/meili-NG/meiliNG/v2/pkg/notify/providers"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/pkg/notify"
	"github.com/meili-NG/meiliNG/v2/pkg/server/helpers"
	"github.com/meili-NG/meiliNG/v2/pkg/telemetry"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"gorm.io/gorm"
)

// Initialize sets up all internal components (database, JWT, etc.)
func (m *Meiling) Initialize() error {
	return m.initialize()
}

// initialize sets up all internal components
// This is called lazily when GetServer() or Run() is invoked
func (m *Meiling) initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		return nil
	}

	meilingErrors.SetConfig(&meilingErrors.Config{
		Debug:             m.config.DebugConfig.Enabled,
		RespondStackTrace: m.config.DebugConfig.RespondStackTrace,
	})

	if err := auth.ValidateConfig(m.config); err != nil {
		return err
	}

	// Fail on a misconfigured captcha provider now, not on the first request.
	if _, err := captcha.For(m.config); err != nil {
		return err
	}

	if provide := telemetry.Provider.Get(); provide != nil {
		reporter, err := provide(m.config)
		if err != nil {
			return err
		}
		m.reporter = reporter
	}

	// Setup database dependencies
	if err := m.setupDatabaseDependencies(); err != nil {
		return err
	}

	// Initialize database
	if err := api.InitializeDatabase(); err != nil {
		return err
	}

	// Initialize JWT
	m.getOrCreateTokenServicesLocked().JWT()

	// Initialize uuid random pool
	uuid.EnableRandPool()

	// Report which notification providers are compiled in and how each key
	// resolves, so operators can confirm the active provider from the logs.
	notify.LogResolution(m.config)

	// Extensions run last so every core dependency is ready. m satisfies
	// ext.Host through Config, which does not take m.mu, so hooks cannot
	// deadlock on the lock held here.
	if err := ext.RunInitializers(context.Background(), m); err != nil {
		return err
	}

	m.initialized = true
	return nil
}

// setupDatabaseDependencies configures database-related dependencies
func (m *Meiling) setupDatabaseDependencies() error {
	cfg := m.config

	var providedGeoIP geoip.ResolveFunc
	if provide := geoip.Provider.Get(); provide != nil {
		resolver, err := provide(cfg)
		if err != nil {
			return fmt.Errorf("geoip: %w", err)
		}
		providedGeoIP = resolver
	}

	var resolveAvatar avatar.ResolveFunc
	if provide := avatar.Provider.Get(); provide != nil {
		resolver, err := provide(cfg)
		if err != nil {
			return fmt.Errorf("avatar: %w", err)
		}
		resolveAvatar = resolver
	}

	// Set database config
	dbCfg := &api.DatabaseConfig{}
	utils.CopyFields(&cfg.DatabaseConfig, dbCfg)
	api.SetDatabaseConfig(dbCfg)

	// Set dependencies - closures capture the config
	api.SetDependencies(&api.Dependencies{
		WebAuthn: func() (*webauthn.WebAuthn, error) {
			return helpers.NewWebAuthn(cfg)
		},
		IsValidOAuth2URI: validator.IsValidOAuth2URI,
		GeneralizePhone: func(phone string) (string, error) {
			return common.GeneralizePhone(cfg, phone)
		},
		GetDialector: func(dbCfg *api.DatabaseConfig) gorm.Dialector {
			// Convert to config for dialector
			cmCfg := &config.DatabaseConfig{}
			utils.CopyFields(dbCfg, cmCfg)
			return cmCfg.GetDialector()
		},
		ResolveGeoIP: func(ip string) (*database.GeoIPResult, error) {
			if resolver := m.getGeoIPResolver(); resolver != nil {
				return resolver(ip)
			}
			if providedGeoIP != nil {
				return providedGeoIP(ip)
			}
			return nil, nil
		},
		ResolveAvatar: resolveAvatar,
	})
	return nil
}

func (m *Meiling) getOrCreateTokenServicesLocked() *tokens.Services {
	if m.tokenServices == nil {
		m.tokenServices = tokens.NewServices(m.config)
	}
	return m.tokenServices
}
