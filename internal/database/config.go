package database

import (
	"sync/atomic"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/meili-NG/meiliNG/v2/pkg/avatar"
	"github.com/meili-NG/meiliNG/v2/pkg/geoip"
	"gorm.io/gorm"
)

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	Type  string
	DSN   string
	Debug bool
}

// GeoIPResult is the public geoip.Result, aliased so the database layer and
// external resolvers share one type.
type GeoIPResult = geoip.Result

// Dependencies holds external dependencies for the database package
type Dependencies struct {
	// WebAuthn returns a configured WebAuthn instance
	WebAuthn func() (*webauthn.WebAuthn, error)

	// IsValidOAuth2URI checks if a URI is a valid OAuth2 redirect URI
	IsValidOAuth2URI func(uri string) bool

	// GeneralizePhone normalizes a phone number to E.164 format
	GeneralizePhone func(phone string) (string, error)

	// GetDialector returns a GORM dialector for the database type
	GetDialector func(cfg *DatabaseConfig) gorm.Dialector

	// ResolveGeoIP resolves a request IP into stored, queryable GeoIP fields.
	ResolveGeoIP func(ip string) (*GeoIPResult, error)

	// ResolveAvatar is the picture of users without an uploaded avatar, from
	// avatar.Provider. Nil means none.
	ResolveAvatar avatar.ResolveFunc
}

// These are atomic because a configuration reload replaces them while
// requests read them.
var globalDeps atomic.Pointer[Dependencies]
var globalDBConfig atomic.Pointer[DatabaseConfig]

// SetDependencies sets the global dependencies for the database package
func SetDependencies(deps *Dependencies) {
	globalDeps.Store(deps)
}

// GetDependencies returns the global dependencies
func GetDependencies() *Dependencies {
	return globalDeps.Load()
}

// SetDatabaseConfig sets the global database configuration
func SetDatabaseConfig(cfg *DatabaseConfig) {
	globalDBConfig.Store(cfg)
}

// GetDatabaseConfig returns the global database configuration
func GetDatabaseConfig() *DatabaseConfig {
	return globalDBConfig.Load()
}
