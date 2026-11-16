package validator

import (
	"slices"
	"strings"
)

// IsValidURL checks if a URL starts with http:// or https://
func IsValidURL(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

var ietfRedirectURIs = []string{
	"urn:ietf:wg:oauth:2.0:oob",
	"urn:ietf:wg:oauth:2.0:oob:auto",
}

// IsValidOAuth2URI checks if a URI is a valid IETF OAuth2 redirect URI
func IsValidOAuth2URI(uri string) bool {
	return slices.Contains(ietfRedirectURIs, uri)
}

// IsValidRedirectURI checks if a redirect URI is valid (either a URL or OAuth2 IETF URI)
func IsValidRedirectURI(redirectURI string) bool {
	return IsValidURL(redirectURI) || IsValidOAuth2URI(redirectURI)
}
