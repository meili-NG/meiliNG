package v2

import "github.com/go-jose/go-jose/v4"

// JWKSInput represents the input for JWKS (empty)
type JWKSInput struct{}

// JWKSOutput represents the output for JWKS
type JWKSOutput struct {
	Body jose.JSONWebKeySet
}
