package api

import (
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"gorm.io/gorm"
)

// DatabaseConfig wraps the database configuration
type DatabaseConfig = database.DatabaseConfig

// Dependencies wraps database dependencies
type Dependencies = database.Dependencies

// SetDatabaseConfig sets the database configuration
func SetDatabaseConfig(cfg *DatabaseConfig) {
	database.SetDatabaseConfig(cfg)
}

// SetDependencies sets the database dependencies
func SetDependencies(deps *Dependencies) {
	database.SetDependencies(deps)
}

// InitializeDatabase initializes the database connection
func InitializeDatabase() error {
	return database.Initialize()
}

// GetDialectorFunc is a function type for getting a GORM dialector
type GetDialectorFunc = func(cfg *DatabaseConfig) gorm.Dialector
