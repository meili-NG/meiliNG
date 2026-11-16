package validator

import "testing"

func TestIsValidPassword(t *testing.T) {
	t.Parallel()

	if IsValidPassword("short") {
		t.Fatalf("expected short password to be invalid")
	}
	if !IsValidPassword("long-enough") {
		t.Fatalf("expected long password to be valid")
	}
}

func TestIsValidUsername(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		username string
		want     bool
	}{
		{name: "alphanumeric", username: "User123", want: true},
		{name: "blank", username: "   ", want: false},
		{name: "email address", username: "user@example.com", want: false},
		{name: "symbol", username: "user-name", want: false},
	}

	for _, tt := range tests {
		if got := IsValidUsername(tt.username); got != tt.want {
			t.Fatalf("%s: IsValidUsername(%q) = %v, want %v", tt.name, tt.username, got, tt.want)
		}
	}
}

func TestRedirectValidation(t *testing.T) {
	t.Parallel()

	if !IsValidURL("https://example.com/callback") {
		t.Fatalf("expected https URL to be valid")
	}
	if IsValidURL("ftp://example.com/callback") {
		t.Fatalf("expected non-http URL to be invalid")
	}

	if !IsValidOAuth2URI("urn:ietf:wg:oauth:2.0:oob") {
		t.Fatalf("expected known IETF redirect URI to be valid")
	}
	if IsValidOAuth2URI("urn:ietf:wg:oauth:2.0:unknown") {
		t.Fatalf("expected unknown IETF redirect URI to be invalid")
	}

	if !IsValidRedirectURI("https://example.com/callback") {
		t.Fatalf("expected URL redirect URI to be valid")
	}
	if !IsValidRedirectURI("urn:ietf:wg:oauth:2.0:oob:auto") {
		t.Fatalf("expected IETF redirect URI to be valid")
	}
	if IsValidRedirectURI("javascript:alert(1)") {
		t.Fatalf("expected unsupported redirect URI to be invalid")
	}
}
