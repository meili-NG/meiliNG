package database

import (
	"testing"

	"github.com/meili-NG/meiliNG/v2/internal/models"
)

func TestValidateRedirectURILoopbackMatchesAnyPort(t *testing.T) {
	ResetInstance()
	var redirects []OauthRedirectURI
	for _, uri := range []string{
		"http://127.0.0.1/callback",
		"http://[::1]/callback",
		"http://localhost/callback",
		"https://app.example.com:8443/callback",
	} {
		redirects = append(redirects, OauthRedirectURI{models.OAuthRedirectURIFields{URI: uri}})
	}
	client := &OauthClient{RedirectURIs: redirects}

	cases := []struct {
		target string
		want   bool
	}{
		// RFC 8252 §7.3: any port on a registered loopback IP literal.
		{"http://127.0.0.1:51671/callback", true},
		{"http://127.0.0.1/callback", true},
		{"http://[::1]:40000/callback", true},
		// Path, scheme and host still have to match.
		{"http://127.0.0.1:51671/other", false},
		{"https://127.0.0.1:51671/callback", false},
		{"http://127.0.0.2:51671/callback", false},
		{"http://[::1]:40000/other", false},
		// "localhost" is not a loopback IP literal (§8.3): exact matching only.
		{"http://localhost/callback", true},
		{"http://localhost:51671/callback", false},
		// Everything else keeps exact port matching.
		{"https://app.example.com:8443/callback", true},
		{"https://app.example.com:9443/callback", false},
		{"https://app.example.com/callback", false},
	}
	for _, tc := range cases {
		if got := client.ValidateRedirectURI(tc.target); got != tc.want {
			t.Errorf("ValidateRedirectURI(%q) = %t, want %t", tc.target, got, tc.want)
		}
	}
}

// A host is compared as lowercase ASCII: one that only matches after a Unicode
// case fold names another domain to a browser.
func TestValidateRedirectURIRejectsNonASCIIHosts(t *testing.T) {
	ResetInstance()
	client := &OauthClient{RedirectURIs: []OauthRedirectURI{
		{models.OAuthRedirectURIFields{URI: "https://mysite.example.com/callback"}},
		{models.OAuthRedirectURIFields{URI: "https://k.example.com/callback"}},
	}}

	for target, want := range map[string]bool{
		"https://mysite.example.com/callback":       true,
		"https://MySite.Example.COM/callback":       true,
		"HTTPS://mysite.example.com/callback":       true,
		"https://mys\u0130te.example.com/callback":  false,
		"https://mys%C4%B0te.example.com/callback":  false,
		"https://\u212A.example.com/callback":       false,
		"https://mysite.ex\u0430mple.com/callback":  false,
		"https://mysite.example.com\u3002/callback": false,
	} {
		if got := client.ValidateRedirectURI(target); got != want {
			t.Errorf("ValidateRedirectURI(%q) = %t, want %t", target, got, want)
		}
	}
}
