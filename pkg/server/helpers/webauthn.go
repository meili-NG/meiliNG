package helpers

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

var webAuthn *webauthn.WebAuthn

func NewWebAuthn(cfg *config.MeilingConfig) (*webauthn.WebAuthn, error) {
	if webAuthn != nil {
		return webAuthn, nil
	}

	webauthnConfig := &webauthn.Config{
		RPDisplayName: cfg.AuthConfig.WebAuthn.DisplayName,
		RPID:          cfg.AuthConfig.WebAuthn.RelyingPartyID,
		RPOrigins:     cfg.AuthConfig.WebAuthn.RelyingPartyOrigins,
	}

	res, err := webauthn.New(webauthnConfig)
	if err != nil {
		return nil, err
	}

	webAuthn = res
	return webAuthn, nil
}
