package config

import (
	"testing"
	"time"
)

func TestTokenConfigPostProcessDefaults(t *testing.T) {
	t.Parallel()

	cfg := TokenConfig{}
	if err := cfg.PostProcess(); err != nil {
		t.Fatalf("PostProcess: %v", err)
	}
	if cfg.Session.Duration != 120*time.Hour {
		t.Fatalf("Duration = %v, want 120h", cfg.Session.Duration)
	}
	if cfg.Session.RenewalThreshold != 36*time.Hour {
		t.Fatalf("RenewalThreshold = %v, want 36h", cfg.Session.RenewalThreshold)
	}
	if cfg.AccessToken.Duration != time.Hour {
		t.Fatalf("AccessToken.Duration = %v, want 1h", cfg.AccessToken.Duration)
	}
	if cfg.RefreshToken.Duration != 168*time.Hour {
		t.Fatalf("RefreshToken.Duration = %v, want 168h", cfg.RefreshToken.Duration)
	}
	if cfg.OwnershipToken.Duration != time.Hour {
		t.Fatalf("OwnershipToken.Duration = %v, want 1h", cfg.OwnershipToken.Duration)
	}
	if cfg.OwnershipChallenge.Duration != 10*time.Minute {
		t.Fatalf("OwnershipChallenge.Duration = %v, want 10m", cfg.OwnershipChallenge.Duration)
	}
	if cfg.AuthorizationCode.Duration != 10*time.Minute {
		t.Fatalf("AuthorizationCode.Duration = %v, want 10m", cfg.AuthorizationCode.Duration)
	}
	if cfg.DeviceCode.Duration != 15*time.Minute {
		t.Fatalf("DeviceCode.Duration = %v, want 15m", cfg.DeviceCode.Duration)
	}
	if cfg.ResourceRegister.Duration != 10*time.Minute {
		t.Fatalf("ResourceRegister.Duration = %v, want 10m", cfg.ResourceRegister.Duration)
	}
	if cfg.IDToken.Duration != 24*time.Hour {
		t.Fatalf("IDToken.Duration = %v, want 24h", cfg.IDToken.Duration)
	}
}

func TestTokenConfigPostProcessConfiguredValues(t *testing.T) {
	t.Parallel()

	cfg := TokenConfig{
		Session: SessionConfig{
			DurationString:         "12h",
			RenewalThresholdString: "36h",
		},
		AccessToken: ManagedTokenConfig{
			DurationString: "30m",
		},
		RefreshToken: ManagedTokenConfig{
			DurationString: "48h",
		},
		OwnershipToken: ManagedTokenConfig{
			DurationString: "2h",
		},
		OwnershipChallenge: ManagedTokenConfig{
			DurationString: "15m",
		},
		AuthorizationCode: ManagedTokenConfig{
			DurationString: "7m",
		},
		DeviceCode: ManagedTokenConfig{
			DurationString: "9m",
		},
		ResourceRegister: ManagedTokenConfig{
			DurationString: "12m",
		},
		IDToken: ManagedTokenConfig{
			DurationString: "6h",
		},
	}
	if err := cfg.PostProcess(); err != nil {
		t.Fatalf("PostProcess: %v", err)
	}
	if cfg.Session.Duration != 12*time.Hour {
		t.Fatalf("Duration = %v, want 12h", cfg.Session.Duration)
	}
	if cfg.Session.RenewalThreshold != 36*time.Hour {
		t.Fatalf("RenewalThreshold = %v, want 36h", cfg.Session.RenewalThreshold)
	}
	if cfg.AccessToken.Duration != 30*time.Minute {
		t.Fatalf("AccessToken.Duration = %v, want 30m", cfg.AccessToken.Duration)
	}
	if cfg.RefreshToken.Duration != 48*time.Hour {
		t.Fatalf("RefreshToken.Duration = %v, want 48h", cfg.RefreshToken.Duration)
	}
	if cfg.OwnershipToken.Duration != 2*time.Hour {
		t.Fatalf("OwnershipToken.Duration = %v, want 2h", cfg.OwnershipToken.Duration)
	}
	if cfg.OwnershipChallenge.Duration != 15*time.Minute {
		t.Fatalf("OwnershipChallenge.Duration = %v, want 15m", cfg.OwnershipChallenge.Duration)
	}
	if cfg.AuthorizationCode.Duration != 7*time.Minute {
		t.Fatalf("AuthorizationCode.Duration = %v, want 7m", cfg.AuthorizationCode.Duration)
	}
	if cfg.DeviceCode.Duration != 9*time.Minute {
		t.Fatalf("DeviceCode.Duration = %v, want 9m", cfg.DeviceCode.Duration)
	}
	if cfg.ResourceRegister.Duration != 12*time.Minute {
		t.Fatalf("ResourceRegister.Duration = %v, want 12m", cfg.ResourceRegister.Duration)
	}
	if cfg.IDToken.Duration != 6*time.Hour {
		t.Fatalf("IDToken.Duration = %v, want 6h", cfg.IDToken.Duration)
	}
}
