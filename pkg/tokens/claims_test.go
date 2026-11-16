package tokens

import (
	"encoding/base64"
	stdjson "encoding/json"
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

const customNamespace = "https://claims.example.com/v2/"

func newNamespacedManager(t *testing.T, privateKeyPath, publicKeyPath, ns string, accepting ...string) *JWTManager {
	t.Helper()
	return NewJWTManager(&config.MeilingConfig{
		TokenConfig: config.TokenConfig{JWT: config.JwtConfig{
			Algorithm:                 "RS256",
			Issuer:                    "https://issuer.example.com",
			PrivateKeyPath:            privateKeyPath,
			PublicKeyPath:             publicKeyPath,
			ClaimsNamespace:           ns,
			AcceptingClaimsNamespaces: accepting,
		}},
	})
}

func issueAccessToken(t *testing.T, m *JWTManager) string {
	t.Helper()
	token, err := m.GenerateTokenWithPrivateClaims(m.GetClaims(), JWTGlobalPrivateClaims{
		TokenType: TokenTypeAccessToken,
		GrantType: "client_credentials",
	})
	if err != nil {
		t.Fatalf("GenerateTokenWithPrivateClaims: %v", err)
	}
	return token
}

func payloadKeys(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]any
	if err := stdjson.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return payload
}

func TestClaimsIssuedUnderDefaultNamespace(t *testing.T) {
	priv, pub := generateJWTIssuerValidationKeyPair(t)
	m := newNamespacedManager(t, priv, pub, "")

	payload := payloadKeys(t, issueAccessToken(t, m))
	if payload[CanonicalClaimsNamespace+"token_type"] != TokenTypeAccessToken {
		t.Fatalf("payload = %v, want token_type under %q", payload, CanonicalClaimsNamespace)
	}
}

func TestClaimsRoundTripUnderConfiguredNamespace(t *testing.T) {
	priv, pub := generateJWTIssuerValidationKeyPair(t)
	m := newNamespacedManager(t, priv, pub, customNamespace)
	token := issueAccessToken(t, m)

	payload := payloadKeys(t, token)
	if payload[customNamespace+"token_type"] != TokenTypeAccessToken || payload[customNamespace+"grant_type"] != "client_credentials" {
		t.Fatalf("payload = %v, want private claims under %q", payload, customNamespace)
	}
	for key := range payload {
		if strings.HasPrefix(key, CanonicalClaimsNamespace) {
			t.Fatalf("canonical claim %q leaked onto the wire", key)
		}
	}

	private, err := m.ParseTokenPrivateClaims(token)
	if err != nil {
		t.Fatalf("ParseTokenPrivateClaims: %v", err)
	}
	if private.TokenType != TokenTypeAccessToken || private.GrantType != "client_credentials" {
		t.Fatalf("parsed private claims = %+v", private)
	}
}

func TestClaimsNamespaceChangeHonorsAcceptingNamespaces(t *testing.T) {
	priv, pub := generateJWTIssuerValidationKeyPair(t)
	acceptedToken := issueAccessToken(t, newNamespacedManager(t, priv, pub, customNamespace))

	accepting := newNamespacedManager(t, priv, pub, "", customNamespace)
	private, err := accepting.ParseTokenPrivateClaims(acceptedToken)
	if err != nil {
		t.Fatalf("ParseTokenPrivateClaims: %v", err)
	}
	if private.TokenType != TokenTypeAccessToken || private.GrantType != "client_credentials" {
		t.Fatalf("token not honored via acceptingClaimsNamespaces: %+v", private)
	}

	strict := newNamespacedManager(t, priv, pub, "")
	private, err = strict.ParseTokenPrivateClaims(acceptedToken)
	if err != nil {
		t.Fatalf("ParseTokenPrivateClaims: %v", err)
	}
	if private.TokenType != "" || private.GrantType != "" {
		t.Fatalf("claims under an unaccepted namespace were honored: %+v", private)
	}
}

func TestCanonicalClaimsIgnoredUnderOtherNamespace(t *testing.T) {
	priv, pub := generateJWTIssuerValidationKeyPair(t)
	canonicalToken := issueAccessToken(t, newNamespacedManager(t, priv, pub, ""))

	other := newNamespacedManager(t, priv, pub, customNamespace)
	private, err := other.ParseTokenPrivateClaims(canonicalToken)
	if err != nil {
		t.Fatalf("ParseTokenPrivateClaims: %v", err)
	}
	if private.GrantType != "" {
		t.Fatal("canonical-namespace claim honored by an instance configured for another namespace")
	}
}

func TestDefaultClaimsNamespaceOverride(t *testing.T) {
	t.Cleanup(DefaultClaimsNamespace.Reset)
	DefaultClaimsNamespace.Override(customNamespace)

	priv, pub := generateJWTIssuerValidationKeyPair(t)
	if ns := newNamespacedManager(t, priv, pub, "").ClaimsNamespace(); ns != customNamespace {
		t.Fatalf("ClaimsNamespace = %q, want the overridden default", ns)
	}
	if ns := newNamespacedManager(t, priv, pub, "https://config.example/").ClaimsNamespace(); ns != "https://config.example/" {
		t.Fatalf("ClaimsNamespace = %q, want token.jwt.claimsNamespace to win over the default", ns)
	}
}

func TestIDTokenContentMarshalUsesNamespace(t *testing.T) {
	content := IDTokenContent{IDTokenPayload: IDTokenPayload{ConsentLogID: "log-1"}}

	raw, err := stdjson.Marshal(content.WithClaimsNamespace(customNamespace))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := stdjson.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got[customNamespace+"oauth2_consent_log_id"] != "log-1" {
		t.Fatalf("userinfo body = %s, want consent log id under %q", raw, customNamespace)
	}
	if _, leaked := got[CanonicalClaimsNamespace+"oauth2_consent_log_id"]; leaked {
		t.Fatalf("canonical claim leaked: %s", raw)
	}
}
