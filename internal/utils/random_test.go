package utils

import (
	"crypto/rand"
	"errors"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy source unavailable")
}

func TestRandomStringPanicsWhenTheEntropySourceFails(t *testing.T) {
	original := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = original }()

	defer func() {
		if recover() == nil {
			t.Fatal("RandomString returned a value without a working entropy source")
		}
	}()
	RandomString(32)
}

func TestRandomStringUsesTheCharset(t *testing.T) {
	got := RandomStringWithCharset(64, "ab")
	if len(got) != 64 {
		t.Fatalf("length = %d, want 64", len(got))
	}
	for _, c := range got {
		if c != 'a' && c != 'b' {
			t.Fatalf("character %q is outside the charset", c)
		}
	}
}
