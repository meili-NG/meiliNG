package tokens

import (
	"crypto/ecdsa"
	"crypto/rsa"
	stdjson "encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
)

type JWTManager struct {
	mu sync.Mutex

	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey

	privateECDSAKey *ecdsa.PrivateKey
	publicECDSAKey  *ecdsa.PublicKey

	algorithm           string
	acceptingAlgorithms []string

	issuer           string
	acceptingIssuers []string

	keyID            string
	verificationKeys []jwtVerificationKey

	signer jose.Signer

	claims claimsNamespaces
}

type jwtVerificationKey struct {
	Key   any
	KeyID string
}

type JWTGlobalPrivateClaims struct {
	TokenType string `json:"urn:meiling:claims:v2:token_type"`
	GrantType string `json:"urn:meiling:claims:v2:grant_type,omitempty"`

	// Extra are private claims a distribution adds (see AccessTokenClaims),
	// keyed by name without the namespace. They never replace core claims.
	Extra map[string]any `json:"-"`

	// scope is a registered claim, so it carries no namespace.
	Scope string `json:"scope,omitempty"`
}
type ExtendedJWTClaims struct {
	jwt.Claims
	KeyID string `json:"kid,omitempty"`
}

func (m *JWTManager) GetClaims() *ExtendedJWTClaims {
	targetClaims := ExtendedJWTClaims{
		Claims: jwt.Claims{
			Issuer:    m.issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		KeyID: m.keyID,
	}

	return &targetClaims
}

func (m *JWTManager) GetJWK() *jose.JSONWebKey {
	keys := m.GetJWKs()
	if len(keys) == 0 {
		return nil
	}

	return &keys[0]
}

func (m *JWTManager) GetJWKs() []jose.JSONWebKey {
	if len(m.verificationKeys) == 0 {
		return nil
	}

	keys := make([]jose.JSONWebKey, 0, len(m.verificationKeys))
	for _, verificationKey := range m.verificationKeys {
		keys = append(keys, jose.JSONWebKey{
			Key:       verificationKey.Key,
			KeyID:     verificationKey.KeyID,
			Algorithm: m.algorithm,
			Use:       "sig",
		})
	}

	return keys
}

func (m *JWTManager) GenerateToken(claims *ExtendedJWTClaims, tokenType string) (string, error) {
	return m.GenerateTokenWithPrivateClaims(claims, JWTGlobalPrivateClaims{TokenType: tokenType})
}

func (m *JWTManager) GenerateTokenWithPrivateClaims(claims *ExtendedJWTClaims, privateClaims JWTGlobalPrivateClaims) (string, error) {
	return m.GenerateTokenFromCustomClaimsWithPrivateClaims(claims, privateClaims)
}

func (m *JWTManager) GenerateTokenFromCustomClaims(claims any, tokenType string) (string, error) {
	return m.GenerateTokenFromCustomClaimsWithPrivateClaims(claims, JWTGlobalPrivateClaims{TokenType: tokenType})
}

func (m *JWTManager) GenerateTokenFromCustomClaimsWithPrivateClaims(claims any, privateClaims JWTGlobalPrivateClaims) (string, error) {
	signer, err := m.provisionSigner()
	if err != nil {
		return "", err
	}

	payload, err := m.claims.encode(claims)
	if err != nil {
		return "", err
	}
	if privateClaims.TokenType != "" {
		private, err := m.claims.encode(privateClaims)
		if err != nil {
			return "", err
		}
		for key, value := range private {
			payload[key] = value
		}
		if len(privateClaims.Extra) > 0 {
			namespaced := make(map[string]any, len(privateClaims.Extra))
			for key, value := range privateClaims.Extra {
				namespaced[CanonicalClaimsNamespace+key] = value
			}
			extra, err := m.claims.encode(namespaced)
			if err != nil {
				return "", err
			}
			for key, value := range extra {
				if _, taken := payload[key]; !taken {
					payload[key] = value
				}
			}
		}
	}

	// go-jose only accepts structs and map[string]any as claims.
	object := make(map[string]any, len(payload))
	for key, value := range payload {
		object[key] = value
	}
	return jwt.Signed(signer).Claims(object).Serialize()
}

// ClaimsNamespace returns the namespace private claims are issued under.
func (m *JWTManager) ClaimsNamespace() string {
	return m.claims.active
}

func (m *JWTManager) setupKeys() error {
	_, err := m.provisionSigner()
	if err != nil {
		return err
	}

	return nil
}

func (m *JWTManager) GetAcceptableAlgorithms() []jose.SignatureAlgorithm {
	if m.acceptingAlgorithms == nil || len(m.acceptingAlgorithms) == 0 {
		return []jose.SignatureAlgorithm{
			jose.SignatureAlgorithm(m.algorithm),
		}
	}

	algorithms := []string{
		m.algorithm,
	}

	for _, a := range m.acceptingAlgorithms {
		if !utils.Contains(algorithms, a) {
			algorithms = append(algorithms, a)
		}
	}

	return utils.Map(algorithms, func(s string) jose.SignatureAlgorithm {
		return jose.SignatureAlgorithm(s)
	})
}

// parseSigned does not verify the signature; ParseTokenClaims does.
func (m *JWTManager) parseSigned(token string) (*jwt.JSONWebToken, error) {
	err := m.setupKeys()
	if err != nil {
		return nil, err
	}

	res, err := jwt.ParseSigned(token, m.GetAcceptableAlgorithms())

	if err != nil {
		thisError := meilingErrors.New(meilingErrors.ErrInvalidToken, err.Error())
		return nil, thisError
	}

	return res, nil
}

// Issuer returns the issuer this manager signs tokens with. Unlike
// validateIssuer it never includes the extra accepting issuers.
func (m *JWTManager) Issuer() string {
	return m.issuer
}

func (m *JWTManager) validateIssuer(claims jwt.Claims) bool {
	if claims.Issuer == m.issuer {
		return true
	}

	return utils.Contains(m.acceptingIssuers, claims.Issuer)
}

func (m *JWTManager) parseAndValidateClaims(token string, destinations ...any) (*jwt.Claims, error) {
	object, err := m.parseSigned(token)
	if err != nil {
		return nil, err
	}

	// Verify into raw bytes first so private claim names can be mapped from
	// the wire namespace to the canonical one the destinations are tagged with.
	var verified stdjson.RawMessage
	if err := m.claimsWithVerificationKeys(object, &verified); err != nil {
		return nil, err
	}
	payload, err := m.claims.decode(verified)
	if err != nil {
		return nil, meilingErrors.New(meilingErrors.ErrInvalidToken, err.Error())
	}

	claims := jwt.Claims{}
	for _, destination := range append([]any{&claims}, destinations...) {
		if err := stdjson.Unmarshal(payload, destination); err != nil {
			return nil, err
		}
	}

	if !m.validateIssuer(claims) {
		return nil, errors.New("invalid issuer")
	}

	return &claims, nil
}

func (m *JWTManager) ParseTokenClaims(token string) (*jwt.Claims, error) {
	claims, err := m.parseAndValidateClaims(token)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (m *JWTManager) ParseTokenPrivateClaims(token string) (*JWTGlobalPrivateClaims, error) {
	tokenTypeClaims := JWTGlobalPrivateClaims{}
	_, err := m.parseAndValidateClaims(token, &tokenTypeClaims)
	if err != nil {
		return nil, err
	}

	return &tokenTypeClaims, nil
}

func (m *JWTManager) ParseTokenCustomClaims(token string, claims any) error {
	_, err := m.parseAndValidateClaims(token, claims)
	return err
}

func (m *JWTManager) provisionSigner() (jose.Signer, error) {
	if m.signer != nil {
		return m.signer, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signer != nil {
		return m.signer, nil
	}

	alg := jose.SignatureAlgorithm(m.algorithm)
	var signer jose.Signer
	signerOptions := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), m.keyID)

	if m.privateKey == nil && m.privateECDSAKey != nil {
		isECDSACompatible := strings.HasPrefix(m.algorithm, "ES")
		// validate first
		if !isECDSACompatible {
			return nil, errors.New("ECDSA key is provided, but the algorithm is not ECDSA")
		}

		tmp, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: m.privateECDSAKey}, signerOptions)
		if err != nil {
			return nil, err
		}

		signer = tmp
	} else if m.privateKey != nil && m.privateECDSAKey == nil {
		isRSACompatible :=
			strings.HasPrefix(m.algorithm, "RS") || strings.HasPrefix(m.algorithm, "PS")

		// validate first
		if !isRSACompatible {
			return nil, errors.New("RSA key is provided, but the algorithm is not RSA")
		}

		tmp, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: m.privateKey}, signerOptions)
		if err != nil {
			return nil, err
		}

		signer = tmp
	} else {
		panic("Either RSA or ECDSA private key must be provided")
	}

	m.signer = signer
	return signer, nil
}

func (m *JWTManager) verificationKey() any {
	if len(m.verificationKeys) > 0 {
		return m.verificationKeys[0].Key
	}

	if m.publicKey != nil {
		return m.publicKey
	}

	if m.publicECDSAKey != nil {
		return m.publicECDSAKey
	}

	return nil
}

func (m *JWTManager) addVerificationKey(key any, keyID string) {
	if key == nil {
		return
	}

	if keyID == "" {
		keyID = generateKeyID(key)
	}

	for _, verificationKey := range m.verificationKeys {
		if verificationKey.KeyID == keyID {
			return
		}
	}

	m.verificationKeys = append(m.verificationKeys, jwtVerificationKey{
		Key:   key,
		KeyID: keyID,
	})
}

func (m *JWTManager) verificationKeysForToken(object *jwt.JSONWebToken) []jwtVerificationKey {
	if len(m.verificationKeys) == 0 {
		return nil
	}

	if object == nil || len(object.Headers) == 0 || object.Headers[0].KeyID == "" {
		return m.verificationKeys
	}

	headerKeyID := object.Headers[0].KeyID
	keys := make([]jwtVerificationKey, 0, len(m.verificationKeys))

	for _, verificationKey := range m.verificationKeys {
		if verificationKey.KeyID == headerKeyID {
			keys = append(keys, verificationKey)
			break
		}
	}

	for _, verificationKey := range m.verificationKeys {
		if verificationKey.KeyID != headerKeyID {
			keys = append(keys, verificationKey)
		}
	}

	return keys
}

func (m *JWTManager) claimsWithVerificationKeys(object *jwt.JSONWebToken, claims ...any) error {
	keys := m.verificationKeysForToken(object)
	if len(keys) == 0 {
		return errors.New("no public key loaded")
	}

	var lastErr error
	for _, verificationKey := range keys {
		if err := object.Claims(verificationKey.Key, claims...); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	return lastErr
}
