package config

import (
	"errors"
	"strings"
	"time"
)

type TokenConfig struct {
	Session            SessionConfig      `json:"session,omitempty"`
	AccessToken        ManagedTokenConfig `json:"accessToken,omitempty"`
	RefreshToken       ManagedTokenConfig `json:"refreshToken,omitempty"`
	OwnershipToken     ManagedTokenConfig `json:"ownershipToken,omitempty"`
	OwnershipChallenge ManagedTokenConfig `json:"ownershipChallenge,omitempty"`
	AuthorizationCode  ManagedTokenConfig `json:"authorizationCode,omitempty"`
	DeviceCode         ManagedTokenConfig `json:"deviceCode,omitempty"`
	ResourceRegister   ManagedTokenConfig `json:"resourceRegister,omitempty"`
	IDToken            ManagedTokenConfig `json:"idToken,omitempty"`
	JWT                JwtConfig          `json:"jwt,omitempty"`
}

func (c *TokenConfig) PostProcess() error {
	if err := c.Session.PostProcess(); err != nil {
		return err
	}
	if err := c.AccessToken.PostProcess("1h", "access token"); err != nil {
		return err
	}
	if err := c.RefreshToken.PostProcess("168h", "refresh token"); err != nil {
		return err
	}
	if err := c.OwnershipToken.PostProcess("1h", "ownership token"); err != nil {
		return err
	}
	if err := c.OwnershipChallenge.PostProcess("10m", "ownership challenge"); err != nil {
		return err
	}
	if err := c.AuthorizationCode.PostProcess("10m", "authorization code"); err != nil {
		return err
	}
	if err := c.DeviceCode.PostProcess("15m", "device code"); err != nil {
		return err
	}
	if err := c.ResourceRegister.PostProcess("10m", "resource register token"); err != nil {
		return err
	}
	if err := c.IDToken.PostProcess("24h", "id token"); err != nil {
		return err
	}
	return nil
}

type ManagedTokenConfig struct {
	DurationString string        `json:"duration,omitempty"`
	Duration       time.Duration `json:"-"`
}

func (c *ManagedTokenConfig) PostProcess(defaultDuration string, label string) error {
	if c.DurationString == "" {
		c.DurationString = defaultDuration
	}
	duration, err := time.ParseDuration(c.DurationString)
	if err != nil {
		return errors.New("invalid " + strings.TrimSpace(label) + " duration: " + err.Error())
	}
	c.Duration = duration
	return nil
}

type SessionConfig struct {
	DurationString         string        `json:"duration" default:"120h"`
	RenewalThresholdString string        `json:"renewalThreshold" default:"36h"`
	Duration               time.Duration `json:"-"`
	RenewalThreshold       time.Duration `json:"-"`
}

func (c *SessionConfig) PostProcess() error {
	if c.DurationString == "" {
		c.DurationString = "120h"
	}
	duration, err := time.ParseDuration(c.DurationString)
	if err != nil {
		return errors.New("invalid session duration: " + err.Error())
	}
	c.Duration = duration

	if c.RenewalThresholdString == "" {
		c.RenewalThresholdString = "36h"
	}
	renewalThreshold, err := time.ParseDuration(c.RenewalThresholdString)
	if err != nil {
		return errors.New("invalid session renewal threshold: " + err.Error())
	}
	c.RenewalThreshold = renewalThreshold

	return nil
}

type JwtConfig struct {
	KeyID                    string   `json:"keyId"`
	Algorithm                string   `json:"algorithm" default:"RS256"`
	AcceptingAlgorithms      []string `json:"acceptingAlgorithms"`
	Issuer                   string   `json:"issuer"`
	AcceptingIssuers         []string `json:"acceptingIssuers"`
	PrivateKeyPath           string   `json:"privateKeyPath" default:"./jwt.key"`
	PublicKeyPath            string   `json:"publicKeyPath"`
	AdditionalPublicKeyPaths []string `json:"additionalPublicKeyPaths"`

	// ClaimsNamespace prefixes Meiling's private claims (token_type,
	// grant_type, ...) in issued tokens. Empty uses the build's default.
	ClaimsNamespace string `json:"claimsNamespace"`
	// AcceptingClaimsNamespaces are extra namespaces honored when reading
	// tokens, so tokens issued before a namespace change stay valid.
	AcceptingClaimsNamespaces []string `json:"acceptingClaimsNamespaces"`
}

func (c *JwtConfig) PostProcess() error {
	if c.Algorithm != "" {
		c.Algorithm = strings.ToUpper(c.Algorithm)
	}

	return nil
}
