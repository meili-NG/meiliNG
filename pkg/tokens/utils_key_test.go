package tokens

import (
	stdjson "encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// A key setting is a file path. PEM text given in its place is not decoded,
// and its bytes never become the panic value.
func TestLoadPEMReadsOnlyFiles(t *testing.T) {
	const inline = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\ntrailing"

	defer func() {
		err, ok := recover().(error)
		if !ok || !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("loadPEM panic = %v, want a file-not-found error", err)
		}
	}()
	_, _ = loadPEM(inline)
	t.Fatal("loadPEM returned for a path that does not exist")
}

// New key files are private; an existing file keeps the mode its owner gave it.
func TestKeyFileModes(t *testing.T) {
	dir := t.TempDir()

	generated := filepath.Join(dir, "jwt.key")
	if err := generateRSAKey(generated); err != nil {
		t.Fatalf("generateRSAKey: %v", err)
	}
	if info, err := os.Stat(generated); err != nil || info.Mode().Perm() != keyFileMode {
		t.Fatalf("generated key mode = %v (err %v), want %#o", info.Mode().Perm(), err, keyFileMode)
	}

	existing := filepath.Join(dir, "existing.pub")
	if err := os.WriteFile(existing, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(existing, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := savePEM(existing, &pem.Block{Type: "TEST", Bytes: []byte("x")}); err != nil {
		t.Fatalf("savePEM: %v", err)
	}
	if info, err := os.Stat(existing); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("existing file mode = %v (err %v), want it left at 0644", info.Mode().Perm(), err)
	}
}

func TestSessionPayloadMarshalsToJSON(t *testing.T) {
	if _, err := stdjson.Marshal(&SessionPayload{Users: []string{"a"}}); err != nil {
		t.Fatalf("Marshal: %v", err)
	}
}
