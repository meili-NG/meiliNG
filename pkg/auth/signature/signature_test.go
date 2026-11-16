package signature

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

const challenge = "a1b2c3d4e5f6"

func pgpKey(t *testing.T) (*openpgp.Entity, string) {
	t.Helper()
	entity, err := openpgp.NewEntity("Test", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, _ := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err := entity.Serialize(w); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return entity, buf.String()
}

func TestPGP(t *testing.T) {
	signer, public := pgpKey(t)
	_, otherPublic := pgpKey(t)

	if fp, err := ParsePGPKey(public); err != nil || len(fp) != 40 {
		t.Fatalf("ParsePGPKey = %q, %v", fp, err)
	}
	if _, err := ParsePGPKey("not a key"); err == nil {
		t.Fatal("ParsePGPKey accepted garbage")
	}

	clearSigned := func(text string) string {
		var buf bytes.Buffer
		w, err := clearsign.Encode(&buf, signer.PrivateKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(text))
		w.Close()
		return buf.String()
	}
	armoredSigned := func(text string) string {
		var buf bytes.Buffer
		a, _ := armor.Encode(&buf, "PGP MESSAGE", nil)
		w, err := openpgp.Sign(a, signer, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(text))
		w.Close()
		a.Close()
		return buf.String()
	}

	for name, tc := range map[string]struct {
		key, signed string
		want        bool
	}{
		"clearsign":         {public, clearSigned(challenge + "\n"), true},
		"armored message":   {public, armoredSigned(challenge), true},
		"another challenge": {public, clearSigned("something else"), false},
		"another key":       {otherPublic, clearSigned(challenge), false},
		"tampered":          {public, strings.Replace(clearSigned(challenge), challenge, "a1b2c3d4e5f7", 1), false},
		"not a signature":   {public, challenge, false},
	} {
		if got, _ := VerifyPGP(tc.key, tc.signed, challenge); got != tc.want {
			t.Errorf("%s: VerifyPGP = %v, want %v", name, got, tc.want)
		}
	}
}

// The signature comes from the real ssh-keygen, so the SSHSIG parsing is
// checked against OpenSSH rather than against itself.
func TestSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	keygen := func(name string) string {
		path := filepath.Join(dir, name)
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test@example.com", "-f", path).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v %s", err, out)
		}
		pub, _ := os.ReadFile(path + ".pub")
		return string(pub)
	}
	public, otherPublic := keygen("id"), keygen("other")
	sign := func(message, namespace string) string {
		file := filepath.Join(dir, "challenge")
		os.WriteFile(file, []byte(message), 0o600)
		os.Remove(file + ".sig")
		if out, err := exec.Command("ssh-keygen", "-Y", "sign", "-n", namespace, "-f", filepath.Join(dir, "id"), file).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen -Y sign: %v %s", err, out)
		}
		sig, _ := os.ReadFile(file + ".sig")
		return string(sig)
	}

	key, fp, err := ParseSSHKey(public)
	if err != nil || !strings.HasPrefix(fp, "SHA256:") || strings.Contains(key, "test@example.com") {
		t.Fatalf("ParseSSHKey = %q, %q, %v", key, fp, err)
	}

	for name, tc := range map[string]struct {
		key, sig string
		want     bool
	}{
		"signed":            {public, sign(challenge, SSHNamespace), true},
		"signed via echo":   {public, sign(challenge+"\n", SSHNamespace), true},
		"another namespace": {public, sign(challenge, "git"), false},
		"another challenge": {public, sign("something else", SSHNamespace), false},
		"another key":       {otherPublic, sign(challenge, SSHNamespace), false},
		"not a signature":   {public, challenge, false},
	} {
		if got, _ := VerifySSH(tc.key, tc.sig, challenge); got != tc.want {
			t.Errorf("%s: VerifySSH = %v, want %v", name, got, tc.want)
		}
	}
}
