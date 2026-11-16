package database

import (
	"errors"
	"sync"
	"sync/atomic"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// gormInstance is atomic because a configuration reload replaces it while
// requests read it.
var gormInstance atomic.Pointer[gorm.DB]
var initMutex sync.Mutex

func Initialize() (error error) {
	err := InitializeMainDB()
	if err != nil {
		return err
	}

	return nil
}

func InitializeMainDB() error {
	instance, err := GetDatabase()
	if err != nil {
		return err
	}

	err = instance.AutoMigrate(
		&User{}, &UserAuthenticator{}, &UserEmail{}, &UserName{}, &UserPhone{}, &UserData{},
		&Application{}, &ApplicationPolicy{}, &Permission{}, &ApplicationPermission{}, &ApplicationConsentLog{},
		&OauthClient{}, &OauthCredential{}, &OauthRedirectURI{}, &OauthPostLogoutRedirectURI{}, &OauthAudience{}, &OauthClientAudience{},
		&ApplicationSession{},
		&SignInLog{},
	)
	if err != nil {
		return err
	}

	// Seed the standard OIDC scopes so OpenID Connect works out of the box.
	// Idempotent, so it is safe to run on every startup.
	return SeedOIDCPermissions(instance)
}

// ResetInstance clears the cached database instance, forcing re-initialization on the next call.
// This is intended for use in tests that need isolated database instances.
func ResetInstance() {
	ReplaceInstance(nil)
}

// ReplaceInstance sets the cached database instance and returns the previous
// one. nil makes the next GetDatabase connect with the current config.
func ReplaceInstance(db *gorm.DB) *gorm.DB {
	initMutex.Lock()
	defer initMutex.Unlock()
	return gormInstance.Swap(db)
}

func GetDatabase() (instance *gorm.DB, error error) {
	if instance := gormInstance.Load(); instance != nil {
		return instance, nil
	}

	initMutex.Lock()
	defer initMutex.Unlock()
	if instance := gormInstance.Load(); instance != nil {
		return instance, nil
	}

	cfg := GetDatabaseConfig()
	if cfg == nil {
		return nil, errors.New("database config not set - call SetDatabaseConfig first")
	}

	if cfg.DSN == "" {
		return nil, errors.New("database dsn not configured")
	}

	deps := GetDependencies()
	if deps == nil || deps.GetDialector == nil {
		return nil, errors.New("database dependencies not set - call SetDependencies first")
	}

	dialector := deps.GetDialector(cfg)
	if dialector == nil {
		return nil, errors.New("unsupported database type: " + cfg.Type)
	}

	dbLogger := logger.Default.LogMode(logger.Silent)
	if cfg.Debug {
		dbLogger = logger.Default.LogMode(logger.Info)
	}

	instance, err := gorm.Open(dialector, &gorm.Config{
		Logger: dbLogger,
	})
	if err != nil {
		return nil, err
	}

	gormInstance.Store(instance)
	return instance, nil
}

func GetDatabaseWithPreload(preloads ...string) (instance *gorm.DB, error error) {
	instance, err := GetDatabase()
	if err != nil {
		return nil, err
	}

	for _, preload := range preloads {
		instance = instance.Preload(preload)
	}

	return instance, nil
}

func GetDatabaseFull() (instance *gorm.DB, error error) {
	return GetDatabaseWithPreload(clause.Associations)
}
