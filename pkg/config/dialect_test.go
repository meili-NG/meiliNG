package config

import (
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
)

func TestDatabaseDialects(t *testing.T) {
	c := DatabaseConfig{Type: "sqlite"}
	if err := c.PostProcess(); err != nil || c.DSN != "./db.sqlite" {
		t.Fatalf("sqlite PostProcess = %v, DSN %q", err, c.DSN)
	}

	c = DatabaseConfig{Type: "mysql", DSN: "user@tcp(db)/meiling"}
	if err := c.PostProcess(); err != nil || !strings.Contains(c.DSN, "parseTime=True") {
		t.Fatalf("mysql PostProcess = %v, DSN %q", err, c.DSN)
	}

	c = DatabaseConfig{Type: "oracle"}
	if err := c.PostProcess(); err == nil || !strings.Contains(err.Error(), "sqlite") {
		t.Fatalf("unknown type PostProcess = %v, want an error listing registered types", err)
	}

	RegisterDialect("test-dialect", Dialect{Open: sqlite.Open})
	c = DatabaseConfig{Type: "test-dialect", DSN: "file::memory:"}
	if err := c.PostProcess(); err != nil || c.GetDialector() == nil {
		t.Fatalf("registered dialect PostProcess = %v, dialector %v", err, c.GetDialector())
	}
}
