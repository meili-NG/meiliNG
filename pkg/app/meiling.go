package app

import (
	"net"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/gofiber/fiber/v2"
	internalconfig "github.com/meili-NG/meiliNG/v2/internal/config"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/geoip"
	"github.com/meili-NG/meiliNG/v2/pkg/telemetry"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

// Meiling is the main entry point for the Meiling authentication system
type Meiling struct {
	config      *config.MeilingConfig
	configPath  string
	initialized bool
	mu          sync.RWMutex

	geoIPResolver geoip.ResolveFunc
	// reporter is nil when telemetry is off.
	reporter *telemetry.Reporter

	// reloadMu serializes Reload calls.
	reloadMu sync.Mutex
	// current is the app that serves requests once StartServer runs. Reload
	// replaces it; the listening server stays fiberApp.
	current atomic.Pointer[generation]

	// Internal components (lazy initialized)
	fiberApp      *fiber.App
	router        Router
	listener      net.Listener
	tokenServices *tokens.Services
}

// New creates a new Meiling instance
// If cfg is empty (zero value), it auto-discovers configuration from standard locations
// Otherwise, it uses the provided configuration as base and applies environment overrides
func New(cfg config.MeilingConfig) (*Meiling, error) {
	var finalCfg *config.MeilingConfig
	var configPath string

	// Check if config is empty (zero value)
	if reflect.DeepEqual(cfg, config.MeilingConfig{}) {
		// Auto-discover configuration
		loadedCfg, err := internalconfig.LoadConfig()
		if err != nil {
			return nil, err
		}
		finalCfg = loadedCfg
		configPath, _ = internalconfig.FindConfigPath()
	} else {
		// Use provided config and apply env overrides
		finalCfg = &cfg
		if err := finalCfg.PostProcess(); err != nil {
			return nil, err
		}
	}

	return &Meiling{
		config:     finalCfg,
		configPath: configPath,
	}, nil
}

// NewFromPath creates a new Meiling instance from a specific config path
func NewFromPath(path string) (*Meiling, error) {
	cfg, err := internalconfig.LoadConfigWithPath(path)
	if err != nil {
		return nil, err
	}

	return &Meiling{
		config:     cfg,
		configPath: path,
	}, nil
}

// Config returns the current configuration
func (m *Meiling) Config() *config.MeilingConfig {
	return m.config
}

// SaveConfig saves the current configuration to the config file
func (m *Meiling) SaveConfig() error {
	if m.configPath == "" {
		m.configPath = "./config.json"
	}
	return internalconfig.SaveConfig(m.config, m.configPath)
}

// IsInitialized returns whether the Meiling instance has been initialized
func (m *Meiling) IsInitialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.initialized
}

func (m *Meiling) TokenServices() *tokens.Services {
	m.mu.RLock()
	if m.tokenServices != nil {
		defer m.mu.RUnlock()
		return m.tokenServices
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getOrCreateTokenServicesLocked()
}

// TokenServicesLocked returns the token services without taking the instance
// lock. It is only safe to call from code paths that already hold m.mu (e.g.
// route registration inside GetServer), where calling the locking
// TokenServices() would self-deadlock because sync.RWMutex is not reentrant.
func (m *Meiling) TokenServicesLocked() *tokens.Services {
	return m.getOrCreateTokenServicesLocked()
}

// SetGeoIPResolver overrides the GeoIP lookup for this instance, ahead of the
// one geoip.Provider built. It takes the instance lock, so do not call it from
// an ext.Initializer; override geoip.Provider instead.
func (m *Meiling) SetGeoIPResolver(resolver geoip.ResolveFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.geoIPResolver = resolver
}

func (m *Meiling) getGeoIPResolver() geoip.ResolveFunc {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.geoIPResolver
}
