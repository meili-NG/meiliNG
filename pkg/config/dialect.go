package config

import (
	"fmt"
	"sort"
	"sync"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Dialect is a database type selectable with database.type. sqlite, mysql and
// postgres (alias postgresql) are built in; a distribution adds others, such
// as a SQL Server or ClickHouse driver, with RegisterDialect.
type Dialect struct {
	// Prepare normalizes database.dsn when the config loads, for example to
	// fill in a default or required parameters. Nil keeps the DSN as is.
	Prepare func(dsn string) (string, error)
	// Open returns the GORM dialector for dsn.
	Open func(dsn string) gorm.Dialector
}

var (
	dialectsMu sync.RWMutex
	dialects   = map[string]Dialect{}
)

// RegisterDialect makes a database type available under name. It panics on a
// duplicate name or a nil Open, as both are programming errors.
func RegisterDialect(name string, d Dialect) {
	if name == "" || d.Open == nil {
		panic("config: RegisterDialect needs a name and an Open function")
	}
	dialectsMu.Lock()
	defer dialectsMu.Unlock()
	if _, exists := dialects[name]; exists {
		panic(fmt.Sprintf("config: database dialect %q registered twice", name))
	}
	dialects[name] = d
}

// LookupDialect returns the dialect registered under name.
func LookupDialect(name string) (Dialect, bool) {
	dialectsMu.RLock()
	defer dialectsMu.RUnlock()
	d, ok := dialects[name]
	return d, ok
}

// Dialects returns the registered database type names, sorted.
func Dialects() []string {
	dialectsMu.RLock()
	defer dialectsMu.RUnlock()
	names := make([]string, 0, len(dialects))
	for name := range dialects {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func init() {
	RegisterDialect("sqlite", Dialect{
		Prepare: func(dsn string) (string, error) {
			if dsn == "" {
				return "./db.sqlite", nil
			}
			return dsn, nil
		},
		Open: sqlite.Open,
	})
	RegisterDialect("mysql", Dialect{Prepare: prepareMySQLDSN, Open: mysql.Open})
	postgresDialect := Dialect{Open: postgres.Open}
	RegisterDialect("postgres", postgresDialect)
	RegisterDialect("postgresql", postgresDialect)
}
