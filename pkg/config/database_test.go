package config

import "testing"

func TestDatabaseConfigPostProcessForSQLite(t *testing.T) {
	t.Parallel()

	cfg := DatabaseConfig{Type: "sqlite"}
	if err := cfg.PostProcess(); err != nil {
		t.Fatalf("PostProcess: %v", err)
	}
	if cfg.DSN != "./db.sqlite" {
		t.Fatalf("sqlite DSN = %q, want %q", cfg.DSN, "./db.sqlite")
	}
}

func TestDatabaseConfigPostProcessForMySQLAddsParseTime(t *testing.T) {
	t.Parallel()

	cfg := DatabaseConfig{
		Type: "mysql",
		DSN:  "user:pass@tcp(localhost:3306)/meiling",
	}

	if err := cfg.PostProcess(); err != nil {
		t.Fatalf("PostProcess: %v", err)
	}
	if cfg.DSN != "user:pass@tcp(localhost:3306)/meiling?parseTime=True" {
		t.Fatalf("mysql DSN = %q", cfg.DSN)
	}
}
