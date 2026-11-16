package test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	gossh "golang.org/x/crypto/ssh"
)

// signWithKey signs in passwordless with a registered signing key of kind;
// sign turns the issued challenge into the signature to submit.
func signWithKey(t *testing.T, env *featureEnv, identifier, kind string, sign func(challenge string) string) (int, string) {
	t.Helper()
	headers := bearerHeaders(mustCreateSessionToken(t, env))
	resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/signin", map[string]any{"username": identifier}, headers)
	var started struct {
		RequestToken string `json:"requestToken"`
	}
	decodeJSONBody(t, resp, &started)
	query := "?token=" + url.QueryEscape(started.RequestToken) + "&type=" + kind + "&for=passwordless"

	resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/auth/challenge/issue"+query, nil, nil)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var issued struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(raw, &issued); err != nil || issued.Challenge == "" {
		t.Fatalf("issue %s challenge = %d %s", kind, resp.StatusCode, raw)
	}

	for _, step := range []struct {
		path string
		body map[string]any
	}{
		{"/v2/auth/challenge/validate" + query, map[string]any{"response": sign(issued.Challenge)}},
		{"/v2/auth/signin", map[string]any{"challengeToken": started.RequestToken}},
	} {
		resp := mustJSONRequest(t, env.server, http.MethodPost, step.path, step.body, headers)
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, string(raw)
		}
	}
	return http.StatusOK, ""
}

type signingKey struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Public      bool   `json:"public"`
}

func addSigningKey(t *testing.T, env *featureEnv, userID, path, key string) signingKey {
	t.Helper()
	resp := mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/"+userID+path, map[string]any{"key": key, "note": "test"}, adminHeaders())
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s = %d %s", path, resp.StatusCode, raw)
	}
	var added signingKey
	decodeJSONBody(t, resp, &added)
	resp = mustJSONRequest(t, env.server, http.MethodPost, "/v2/users/"+userID+path, map[string]any{"key": key}, adminHeaders())
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("registering the same key twice = %d, want 400", resp.StatusCode)
	}
	return added
}

func setKeyPublic(t *testing.T, env *featureEnv, userID, path, keyID string, public bool) {
	t.Helper()
	resp := mustJSONRequest(t, env.server, http.MethodPatch, "/v2/users/"+userID+path+"?key_id="+keyID, map[string]any{"public": public}, adminHeaders())
	var updated signingKey
	decodeJSONBody(t, resp, &updated)
	if resp.StatusCode != http.StatusOK || updated.Public != public {
		t.Fatalf("PATCH %s public=%v = %d %+v", path, public, resp.StatusCode, updated)
	}
}

func getText(t *testing.T, env *featureEnv, path string) (int, string) {
	t.Helper()
	resp := mustJSONRequest(t, env.server, http.MethodGet, path, nil, nil)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(raw)
}

func TestSignInWithPGPKey(t *testing.T) {
	env := newFeatureEnv(t)
	username := "pgp" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "pgp-password-123", username+"@example.com")

	entity, err := openpgp.NewEntity("Test", "", username+"@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	w, _ := armor.Encode(&public, openpgp.PublicKeyType, nil)
	entity.Serialize(w)
	w.Close()
	added := addSigningKey(t, env, userID, "/pgp-keys", public.String())
	if added.Public || len(added.Fingerprint) != 40 {
		t.Fatalf("added key = %+v, want a private key with a fingerprint", added)
	}

	clearSign := func(challenge string) string {
		var out bytes.Buffer
		w, err := clearsign.Encode(&out, entity.PrivateKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(challenge + "\n"))
		w.Close()
		return out.String()
	}
	if status, body := signWithKey(t, env, username, "pgp", clearSign); status != http.StatusOK {
		t.Fatalf("PGP sign-in = %d %s", status, body)
	}
	if status, _ := signWithKey(t, env, username, "pgp", func(string) string { return clearSign("not the challenge") }); status == http.StatusOK {
		t.Fatal("a signature over another text signed in")
	}
}

func TestSignInWithSSHKey(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	env := newFeatureEnv(t)
	username := "ssh" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "ssh-password-123", username+"@example.com")

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	public, _ := os.ReadFile(keyPath + ".pub")
	addSigningKey(t, env, userID, "/ssh-keys", string(public))

	sign := func(challenge string) string {
		file := filepath.Join(dir, "challenge")
		os.WriteFile(file, []byte(challenge), 0o600)
		os.Remove(file + ".sig")
		if out, err := exec.Command("ssh-keygen", "-Y", "sign", "-n", "meiling", "-f", keyPath, file).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen -Y sign: %v %s", err, out)
		}
		sig, _ := os.ReadFile(file + ".sig")
		return string(sig)
	}
	if status, body := signWithKey(t, env, username, "ssh", sign); status != http.StatusOK {
		t.Fatalf("SSH sign-in = %d %s", status, body)
	}
}

// Keys are private until their owner publishes them, and publishing puts them
// where SSH and GnuPG tooling looks.
func TestPublishedSigningKeys(t *testing.T) {
	env := newFeatureEnv(t)
	mustJSONRequest(t, env.server, http.MethodGet, "/health", nil, nil).Body.Close()
	username := "keys" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "keys-password-123", username+"@example.com")

	edPublic, _, _ := ed25519.GenerateKey(nil)
	sshPublic, _ := gossh.NewPublicKey(edPublic)
	sshKey := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPublic))) + " laptop"
	ssh := addSigningKey(t, env, userID, "/ssh-keys", sshKey)

	entity, err := openpgp.NewEntity("Test", "", username+"@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	var armored bytes.Buffer
	w, _ := armor.Encode(&armored, openpgp.PublicKeyType, nil)
	entity.Serialize(w)
	w.Close()
	pgp := addSigningKey(t, env, userID, "/pgp-keys", armored.String())
	lookup := "/pks/lookup?op=get&search=0x"

	if status, body := getText(t, env, "/"+username+".keys"); status != http.StatusOK || body != "" {
		t.Fatalf("private keys listed: %d %q", status, body)
	}
	if status, _ := getText(t, env, lookup+pgp.Fingerprint); status != http.StatusNotFound {
		t.Fatalf("private PGP key served by the key server: %d", status)
	}

	setKeyPublic(t, env, userID, "/ssh-keys", ssh.ID, true)
	setKeyPublic(t, env, userID, "/pgp-keys", pgp.ID, true)

	if _, body := getText(t, env, "/"+username+".keys"); body != strings.TrimSuffix(sshKey, " laptop")+"\n" {
		t.Fatalf("/%s.keys = %q", username, body)
	}
	if _, body := getText(t, env, "/"+username+".gpg"); !strings.Contains(body, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("/%s.gpg = %q", username, body)
	}
	for _, search := range []string{pgp.Fingerprint, strings.ToUpper(pgp.Fingerprint[24:])} {
		if status, body := getText(t, env, lookup+search); status != http.StatusOK || !strings.Contains(body, "BEGIN PGP PUBLIC KEY BLOCK") {
			t.Fatalf("key server lookup of %s = %d %q", search, status, body)
		}
	}
	if status, body := getText(t, env, "/nobody"+uniqueSuffix()+".keys"); status != http.StatusOK || body != "" {
		t.Fatalf("unknown user = %d %q, want the same empty answer as a user without public keys", status, body)
	}

	setKeyPublic(t, env, userID, "/ssh-keys", ssh.ID, false)
	if _, body := getText(t, env, "/"+username+".keys"); body != "" {
		t.Fatalf("unpublished key still listed: %q", body)
	}

	disabled := newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) { cfg.AuthConfig.DisablePublicKeys = true })
	mustJSONRequest(t, disabled.server, http.MethodGet, "/health", nil, nil).Body.Close()
	if status, _ := getText(t, disabled, "/"+username+".keys"); status != http.StatusNotFound {
		t.Fatalf("auth.disablePublicKeys: /%s.keys = %d, want 404", username, status)
	}
}

// The owner of a key is found by fingerprint only when the instance turned the
// lookup on and the owner published the key.
func TestKeyOwnerLookup(t *testing.T) {
	edPublic, _, _ := ed25519.GenerateKey(nil)
	sshPublic, _ := gossh.NewPublicKey(edPublic)
	sshKey := string(gossh.MarshalAuthorizedKey(sshPublic))
	query := "/v2/keys?fingerprint=" + url.QueryEscape(gossh.FingerprintSHA256(sshPublic))

	off := newFeatureEnv(t)
	if status, _ := getText(t, off, query); status != http.StatusNotFound {
		t.Fatalf("lookup without auth.enableKeyOwnerLookup = %d, want 404", status)
	}

	env := newFeatureEnvWithConfig(t, func(cfg *config.MeilingConfig) { cfg.AuthConfig.EnableKeyOwnerLookup = true })
	username := "owner" + uniqueSuffix()
	userID := mustCreateUser(t, env, username, "owner-password-123", username+"@example.com")
	key := addSigningKey(t, env, userID, "/ssh-keys", sshKey)

	if status, _ := getText(t, env, query); status != http.StatusNotFound {
		t.Fatalf("lookup of a private key = %d, want 404", status)
	}

	setKeyPublic(t, env, userID, "/ssh-keys", key.ID, true)
	status, body := getText(t, env, query)
	var owner struct{ Type, Fingerprint, Username string }
	json.Unmarshal([]byte(body), &owner)
	if status != http.StatusOK || owner.Username != username || owner.Type != "ssh" || owner.Fingerprint != key.Fingerprint {
		t.Fatalf("lookup of a public key = %d %s", status, body)
	}
	if strings.Contains(body, "@example.com") {
		t.Fatalf("lookup revealed an email address: %s", body)
	}
}
