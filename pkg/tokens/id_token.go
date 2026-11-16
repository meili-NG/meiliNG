package tokens

import (
	stdjson "encoding/json"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"time"
)

// TokenTypeIDToken is the token_type private claim of ID tokens.
const TokenTypeIDToken = "id_token"

type IDTokenContent struct {
	jwt.Claims
	IDTokenPayload

	// claimsNamespace, when set, is the namespace MarshalJSON writes private
	// claims under. Tokens get theirs from the JWT manager; this covers
	// responses that serialize the content directly, such as userinfo.
	claimsNamespace string
}

// WithClaimsNamespace returns c set to serialize private claims under ns.
func (c IDTokenContent) WithClaimsNamespace(ns string) IDTokenContent {
	c.claimsNamespace = ns
	return c
}

// MarshalJSON implements json.Marshaler, renaming private claims to the
// namespace set with WithClaimsNamespace.
func (c IDTokenContent) MarshalJSON() ([]byte, error) {
	type plain IDTokenContent
	raw, err := stdjson.Marshal(plain(c))
	if err != nil || c.claimsNamespace == "" || c.claimsNamespace == CanonicalClaimsNamespace {
		return raw, err
	}

	var obj map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	return stdjson.Marshal(renamePrefix(obj, CanonicalClaimsNamespace, c.claimsNamespace))
}

type IDTokenPayload struct {
	ConsentLogID      string  `json:"urn:meiling:claims:v2:oauth2_consent_log_id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Name              string  `json:"name,omitempty" example:"John Doe"`
	GivenName         string  `json:"given_name,omitempty" example:"John"`
	FamilyName        string  `json:"family_name,omitempty" example:"Doe"`
	Locale            *string `json:"locale,omitempty" example:"en-US"`
	ZoneInfo          *string `json:"zoneinfo,omitempty" example:"Etc/UTC"`
	Email             *string `json:"email,omitempty" example:"john.doe@example.com"`
	PhoneNumber       *string `json:"phone_number,omitempty" example:"+12025550123"`
	EmailVerified     *bool   `json:"email_verified,omitempty" example:"true"`
	PhoneVerified     *bool   `json:"phone_number_verified,omitempty" example:"true"`
	Gender            string  `json:"gender,omitempty" enums:"male,female,other"`
	Scope             string  `json:"scope" example:"openid profile email phone"`
	Picture           string  `json:"picture,omitempty" example:"https://example.com/picture.jpg"`
	Profile           string  `json:"profile,omitempty" example:"https://example.com/profile"`
	Nonce             string  `json:"nonce,omitempty" example:"nonce"`
	PreferredUsername string  `json:"preferred_username,omitempty" example:"john.doe"`

	// How the user signed in: the session, when, with what, and how strongly.
	SID      string   `json:"sid,omitempty" example:"123e4567-e89b-12d3-a456-426614174000"`
	AuthTime int64    `json:"auth_time,omitempty" example:"1700000000"`
	AMR      []string `json:"amr,omitempty" example:"pwd,otp,mfa"`
	ACR      string   `json:"acr,omitempty" example:"2fa"`
}

func GenerateIDToken(tokenServices *Services, clientId string, userData IDTokenContent) (string, error) {
	tokenManager := tokenServices.JWT()
	claims := tokenManager.GetClaims()
	cfg := tokenConfig(tokenServices)

	userData.ID = uuid.New().String()
	userData.Issuer = claims.Issuer
	userData.Audience = []string{
		clientId,
	}

	userData.IssuedAt = jwt.NewNumericDate(time.Now())
	userData.Expiry = jwt.NewNumericDate(time.Now().Add(tokenDuration(cfg.IDToken.Duration, defaultTokenConfig().IDToken.Duration)))

	return tokenManager.GenerateTokenFromCustomClaims(userData, TokenTypeIDToken)
}
