package api

import (
	"testing"

	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestPromptBypassIsOptIn(t *testing.T) {
	client := &database.OauthClient{}
	client.BypassConsent = true

	cfg := &config.MeilingConfig{}
	if err := validateOAuth2Prompt(cfg, "bypass", client); err == nil {
		t.Fatal("bypass was allowed without oauth2.enablePromptBypass")
	}
	if err := validateOAuth2Prompt(cfg, "consent", client); err != nil {
		t.Fatalf("a standard prompt = %v", err)
	}

	cfg.OAuth2Config.EnablePromptBypass = true
	if err := validateOAuth2Prompt(cfg, "bypass", client); err != nil {
		t.Fatalf("bypass with enablePromptBypass = %v, want allowed", err)
	}
}
