package config

import "testing"

func TestOAuth2ConfigGetClientSecretLength(t *testing.T) {
	t.Parallel()

	if got := (OAuth2Config{}).GetClientSecretLength(); got != 64 {
		t.Fatalf("default client secret length = %d, want 64", got)
	}

	if got := (OAuth2Config{ClientSecretLength: 96}).GetClientSecretLength(); got != 96 {
		t.Fatalf("configured client secret length = %d, want 96", got)
	}

	if got := (OAuth2Config{ClientSecretLength: -1}).GetClientSecretLength(); got != 64 {
		t.Fatalf("negative client secret length fallback = %d, want 64", got)
	}
}

func TestBackupCodeConfigDefaultsAndClamping(t *testing.T) {
	t.Parallel()

	if got := (BackupCodeConfig{}).GetCount(); got != 10 {
		t.Fatalf("default count = %d, want 10", got)
	}
	if got := (BackupCodeConfig{}).GetMaxCount(); got != 20 {
		t.Fatalf("default max count = %d, want 20", got)
	}
	if got := (BackupCodeConfig{}).GetCodeBytes(); got != 5 {
		t.Fatalf("default code bytes = %d, want 5", got)
	}
	if got := (BackupCodeConfig{Count: 12, MaxCount: 20}).GetCount(); got != 12 {
		t.Fatalf("configured count = %d, want 12", got)
	}
	if got := (BackupCodeConfig{Count: 30, MaxCount: 20}).GetCount(); got != 20 {
		t.Fatalf("clamped count = %d, want 20", got)
	}
	if got := (BackupCodeConfig{Count: -1, MaxCount: 5}).GetCount(); got != 5 {
		t.Fatalf("default count should be clamped to max = %d, want 5", got)
	}
	if got := (BackupCodeConfig{CodeBytes: -1}).GetCodeBytes(); got != 5 {
		t.Fatalf("negative code bytes fallback = %d, want 5", got)
	}
}
