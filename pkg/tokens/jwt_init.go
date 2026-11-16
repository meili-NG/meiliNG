package tokens

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func NewJWTManager(cfg *config.MeilingConfig) *JWTManager {
	if cfg == nil {
		panic("configuration was not provided")
	}

	privateKeyPath, publicKeyPath := cfg.TokenConfig.JWT.PrivateKeyPath, cfg.TokenConfig.JWT.PublicKeyPath
	alg, issuer := cfg.TokenConfig.JWT.Algorithm, cfg.TokenConfig.JWT.Issuer
	acceptingAlgorithms := cfg.TokenConfig.JWT.AcceptingAlgorithms
	acceptingIssuers := cfg.TokenConfig.JWT.AcceptingIssuers

	// check if the private key exists
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		if alg == "RS256" || alg == "PS256" {
			// generate private key
			err := generateRSAKey(privateKeyPath)
			if err != nil {
				panic(err)
			}
		} else {
			panic("Cannot trigger keygen for non-RSA algorithm. generate the key pair manually.")
		}
	}

	var jwtManager *JWTManager
	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
		privateKey := loadRSAPrivateKey(privateKeyPath)
		publicKey := tryLoadRSAPublicKey(publicKeyPath, privateKey)

		jwtManager = &JWTManager{
			keyID:               cfg.TokenConfig.JWT.KeyID,
			privateKey:          privateKey,
			publicKey:           publicKey,
			algorithm:           alg,
			issuer:              issuer,
			acceptingIssuers:    acceptingIssuers,
			acceptingAlgorithms: acceptingAlgorithms,
		}
	} else if strings.HasPrefix(alg, "ES") {
		privateKey := loadECDSAPrivateKey(privateKeyPath)
		publicKey := tryLoadECDSAPublicKey(publicKeyPath, privateKey)

		jwtManager = &JWTManager{
			keyID:               cfg.TokenConfig.JWT.KeyID,
			privateECDSAKey:     privateKey,
			publicECDSAKey:      publicKey,
			algorithm:           alg,
			issuer:              issuer,
			acceptingIssuers:    acceptingIssuers,
			acceptingAlgorithms: acceptingAlgorithms,
		}
	} else {
		panic("Unsupported JWT Algorithm")
	}

	jwtManager.claims = newClaimsNamespaces(cfg.TokenConfig.JWT.ClaimsNamespace, cfg.TokenConfig.JWT.AcceptingClaimsNamespaces)
	jwtManager.SetupKeyID()
	jwtManager.addVerificationKey(jwtManager.verificationKey(), jwtManager.keyID)

	for _, publicKeyPath := range cfg.TokenConfig.JWT.AdditionalPublicKeyPaths {
		publicKeyPath = strings.TrimSpace(publicKeyPath)
		if publicKeyPath == "" {
			continue
		}

		if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
			jwtManager.addVerificationKey(loadRSAPublicKey(publicKeyPath), "")
			continue
		}

		if strings.HasPrefix(alg, "ES") {
			jwtManager.addVerificationKey(loadECDSAPublicKey(publicKeyPath), "")
		}
	}

	return jwtManager
}

func (m *JWTManager) SetupKeyID() string {
	if m.keyID != "" {
		return m.keyID
	}

	m.keyID = generateKeyID(func() any {
		if m.publicKey != nil {
			return m.publicKey
		}

		if m.publicECDSAKey != nil {
			return m.publicECDSAKey
		}

		panic("No public key loaded")
	}())
	return m.keyID
}

func generateKeyID(key any) string {
	hasher := sha256.New()

	switch key := key.(type) {
	case *rsa.PublicKey:
		hasher.Write(key.N.Bytes())
	case *ecdsa.PublicKey:
		hasher.Write(key.X.Bytes())
		hasher.Write(key.Y.Bytes())
	default:
		panic("Unsupported public key type")
	}

	return fmt.Sprintf("%x", hasher.Sum([]byte{}))
}
