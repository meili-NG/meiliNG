package tokens

import (
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"
	gojwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestJWTManagerGetJWKsAndHeadersSupportKeyRotation(t *testing.T) {
	dir := t.TempDir()
	_, oldPublicKeyPath := generateRSAKeyPairForTest(t, dir, "old")
	newPrivateKeyPath, newPublicKeyPath := generateRSAKeyPairForTest(t, dir, "new")

	manager := NewJWTManager(&config.MeilingConfig{
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:                "RS256",
			Issuer:                   "https://issuer.example.com",
			PrivateKeyPath:           newPrivateKeyPath,
			PublicKeyPath:            newPublicKeyPath,
			AdditionalPublicKeyPaths: []string{oldPublicKeyPath},
		}},
	})

	keys := manager.GetJWKs()
	if len(keys) != 2 {
		t.Fatalf("GetJWKs() returned %d keys, want 2", len(keys))
	}

	if keys[0].KeyID != manager.keyID {
		t.Fatalf("active key id = %q, want %q", keys[0].KeyID, manager.keyID)
	}

	if keys[0].Use != "sig" || keys[1].Use != "sig" {
		t.Fatalf("unexpected JWK uses: %#v", keys)
	}

	token, err := manager.GenerateToken(manager.GetClaims(), "access")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	parsed, err := gojwt.ParseSigned(token, manager.GetAcceptableAlgorithms())
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}

	if len(parsed.Headers) == 0 || parsed.Headers[0].KeyID != manager.keyID {
		t.Fatalf("token header kid = %#v, want %q", parsed.Headers, manager.keyID)
	}
}

func TestJWTManagerParseTokenClaimsAcceptsOldKeyTokensAfterRotation(t *testing.T) {
	dir := t.TempDir()
	oldPrivateKeyPath, oldPublicKeyPath := generateRSAKeyPairForTest(t, dir, "old")
	newPrivateKeyPath, newPublicKeyPath := generateRSAKeyPairForTest(t, dir, "new")

	oldManager := NewJWTManager(&config.MeilingConfig{
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:      "RS256",
			Issuer:         "https://issuer.example.com",
			PrivateKeyPath: oldPrivateKeyPath,
			PublicKeyPath:  oldPublicKeyPath,
		}},
	})

	rotatedManager := NewJWTManager(&config.MeilingConfig{
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:                "RS256",
			Issuer:                   "https://issuer.example.com",
			PrivateKeyPath:           newPrivateKeyPath,
			PublicKeyPath:            newPublicKeyPath,
			AdditionalPublicKeyPaths: []string{oldPublicKeyPath},
		}},
	})

	claims := oldManager.GetClaims()
	claims.Subject = "old-key-subject"

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(oldManager.algorithm),
		Key:       oldManager.privateKey,
	}, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	oldKeyToken, err := gojwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	parsedClaims, err := rotatedManager.ParseTokenClaims(oldKeyToken)
	if err != nil {
		t.Fatalf("ParseTokenClaims: %v", err)
	}

	if parsedClaims.Subject != claims.Subject {
		t.Fatalf("parsed subject = %q, want %q", parsedClaims.Subject, claims.Subject)
	}
}

func generateRSAKeyPairForTest(t *testing.T, dir string, prefix string) (string, string) {
	t.Helper()

	privateKeyPath := filepath.Join(dir, prefix+".key")
	publicKeyPath := filepath.Join(dir, prefix+".pub")

	if err := generateRSAKey(privateKeyPath); err != nil {
		t.Fatalf("generateRSAKey(%q): %v", privateKeyPath, err)
	}

	privateKey := loadRSAPrivateKey(privateKeyPath)
	if publicKey := tryLoadRSAPublicKey(publicKeyPath, privateKey); publicKey == nil {
		t.Fatalf("tryLoadRSAPublicKey(%q) returned nil", publicKeyPath)
	}

	return privateKeyPath, publicKeyPath
}
