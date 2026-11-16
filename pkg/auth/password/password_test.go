package password

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestVerify(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("right"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Verify(SchemeBcrypt, string(hash), "right"); !ok || err != nil {
		t.Fatalf("bcrypt right = %v, %v", ok, err)
	}
	if ok, err := Verify(SchemeBcrypt, string(hash), "wrong"); ok || err != nil {
		t.Fatalf("bcrypt wrong = %v, %v; want false without an error", ok, err)
	}

	Register("test-plain", func(stored, password string) (bool, error) { return stored == password, nil })
	if ok, _ := Verify("test-plain", "x", "x"); !ok {
		t.Fatal("a registered scheme was not used")
	}
	if ok, err := Verify("missing", "x", "x"); ok || err == nil {
		t.Fatalf("unknown scheme = %v, %v; want false with an error", ok, err)
	}
}
