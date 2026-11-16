// Package password verifies stored passwords by scheme. A stored password
// records its scheme (bcrypt, or one a distribution adds) next to its data, and
// Verify dispatches on it. Core ships bcrypt; a distribution registers others
// from init(), for example one that binds to a directory server:
//
//	func init() { password.Register("ldap", verifyAgainstDirectory) }
package password

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// Verifier reports whether password matches stored, the data saved for a
// password of its scheme. A mismatch is false with a nil error.
type Verifier func(stored, password string) (bool, error)

// SchemeBcrypt is the scheme of passwords core stores.
const SchemeBcrypt = "bcrypt"

var (
	mu      sync.RWMutex
	schemes = map[string]Verifier{SchemeBcrypt: verifyBcrypt}
)

// Register adds a scheme. It panics on an empty name, a nil verifier or a
// name already taken, which are wiring mistakes.
func Register(scheme string, v Verifier) {
	if scheme == "" || v == nil {
		panic("password: Register needs a scheme name and a verifier")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := schemes[scheme]; dup {
		panic(fmt.Sprintf("password: scheme %q registered twice", scheme))
	}
	schemes[scheme] = v
}

// Verify checks password against stored with the verifier of scheme. An
// unknown scheme never matches.
func Verify(scheme, stored, password string) (bool, error) {
	mu.RLock()
	v, ok := schemes[scheme]
	mu.RUnlock()
	if !ok {
		return false, fmt.Errorf("password: unknown scheme %q", scheme)
	}
	return v(stored, password)
}

func verifyBcrypt(stored, password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	return err == nil, err
}
