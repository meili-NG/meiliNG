package tokens

import (
	"path/filepath"
	"strings"
	"testing"

	gojwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestJWTManagerRejectsUnexpectedIssuerAcrossParseHelpers(t *testing.T) {
	privateKeyPath, publicKeyPath := generateJWTIssuerValidationKeyPair(t)

	verifier := NewJWTManager(&config.MeilingConfig{
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:      "RS256",
			Issuer:         "https://issuer.example.com",
			PrivateKeyPath: privateKeyPath,
			PublicKeyPath:  publicKeyPath,
		}},
	})

	attacker := NewJWTManager(&config.MeilingConfig{
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:      "RS256",
			Issuer:         "https://attacker.example.com",
			PrivateKeyPath: privateKeyPath,
			PublicKeyPath:  publicKeyPath,
		}},
	})

	claims := attacker.GetClaims()
	claims.Subject = "client-123"
	claims.Audience = gojwt.Audience{"https://api.example.com"}

	token, err := attacker.GenerateTokenWithPrivateClaims(claims, JWTGlobalPrivateClaims{
		TokenType: TokenTypeAccessToken,
		GrantType: "client_credentials",
	})
	if err != nil {
		t.Fatalf("GenerateTokenWithPrivateClaims: %v", err)
	}

	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "standard claims",
			fn: func() error {
				_, err := verifier.ParseTokenClaims(token)
				return err
			},
		},
		{
			name: "private claims",
			fn: func() error {
				_, err := verifier.ParseTokenPrivateClaims(token)
				return err
			},
		},
		{
			name: "custom claims",
			fn: func() error {
				var custom struct {
					Subject string `json:"sub,omitempty"`
				}
				return verifier.ParseTokenCustomClaims(token, &custom)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatal("expected invalid issuer error")
			}
			if !strings.Contains(err.Error(), "invalid issuer") {
				t.Fatalf("error = %v, want invalid issuer", err)
			}
		})
	}
}

func TestJWTManagerAcceptsConfiguredAlternateIssuer(t *testing.T) {
	privateKeyPath, publicKeyPath := generateJWTIssuerValidationKeyPair(t)

	verifier := NewJWTManager(&config.MeilingConfig{
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:        "RS256",
			Issuer:           "https://issuer.example.com",
			AcceptingIssuers: []string{"https://alternate.example.com"},
			PrivateKeyPath:   privateKeyPath,
			PublicKeyPath:    publicKeyPath,
		}},
	})

	alternateIssuer := NewJWTManager(&config.MeilingConfig{
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:      "RS256",
			Issuer:         "https://alternate.example.com",
			PrivateKeyPath: privateKeyPath,
			PublicKeyPath:  publicKeyPath,
		}},
	})

	token, err := alternateIssuer.GenerateTokenWithPrivateClaims(alternateIssuer.GetClaims(), JWTGlobalPrivateClaims{
		TokenType: TokenTypeAccessToken,
	})
	if err != nil {
		t.Fatalf("GenerateTokenWithPrivateClaims: %v", err)
	}

	if _, err := verifier.ParseTokenClaims(token); err != nil {
		t.Fatalf("ParseTokenClaims: %v", err)
	}

	if _, err := verifier.ParseTokenPrivateClaims(token); err != nil {
		t.Fatalf("ParseTokenPrivateClaims: %v", err)
	}
}

func generateJWTIssuerValidationKeyPair(t *testing.T) (string, string) {
	t.Helper()

	dir := t.TempDir()
	privateKeyPath := filepath.Join(dir, "jwt.key")
	publicKeyPath := filepath.Join(dir, "jwt.pub")

	if err := generateRSAKey(privateKeyPath); err != nil {
		t.Fatalf("generateRSAKey(%q): %v", privateKeyPath, err)
	}

	privateKey := loadRSAPrivateKey(privateKeyPath)
	if publicKey := tryLoadRSAPublicKey(publicKeyPath, privateKey); publicKey == nil {
		t.Fatalf("tryLoadRSAPublicKey(%q) returned nil", publicKeyPath)
	}

	return privateKeyPath, publicKeyPath
}
