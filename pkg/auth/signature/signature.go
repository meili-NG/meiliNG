// Package signature checks that a user signed a sign-in challenge with a key
// they registered: an OpenPGP key, or an SSH key using the SSHSIG format of
// `ssh-keygen -Y sign`.
package signature

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"golang.org/x/crypto/ssh"
)

// SSHNamespace is the namespace an SSH signature of a sign-in challenge is
// made in: ssh-keygen -Y sign -n meiling -f <key> <file with the challenge>.
const SSHNamespace = "meiling"

// ParsePGPKey checks an armored OpenPGP public key and returns the hex
// fingerprint of its primary key.
func ParsePGPKey(armored string) (string, error) {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return "", fmt.Errorf("parse OpenPGP key: %w", err)
	}
	if len(keyring) != 1 || keyring[0].PrimaryKey == nil {
		return "", errors.New("parse OpenPGP key: expected exactly one public key")
	}
	return hex.EncodeToString(keyring[0].PrimaryKey.Fingerprint), nil
}

// VerifyPGP reports whether signed, a clear-signed message (gpg --clearsign)
// or an armored signed message (gpg --sign --armor), carries challenge and is
// signed by armoredKey.
func VerifyPGP(armoredKey, signed, challenge string) (bool, error) {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredKey))
	if err != nil {
		return false, err
	}

	if block, _ := clearsign.Decode([]byte(signed)); block != nil {
		if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
			return false, nil
		}
		return sameText(string(block.Plaintext), challenge), nil
	}

	decoded, err := armor.Decode(strings.NewReader(signed))
	if err != nil {
		return false, nil
	}
	md, err := openpgp.ReadMessage(decoded.Body, keyring, nil, nil)
	if err != nil || !md.IsSigned || md.SignedBy == nil {
		return false, nil
	}
	body, err := io.ReadAll(md.UnverifiedBody)
	// The signature is checked only once the body has been read to the end.
	if err != nil || md.SignatureError != nil {
		return false, nil
	}
	return sameText(string(body), challenge), nil
}

// ParseSSHKey checks a public key in authorized_keys form and returns it
// without options or comment, with its SHA256 fingerprint.
func ParseSSHKey(authorizedKey string) (key string, fingerprint string, err error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "", "", fmt.Errorf("parse SSH key: %w", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), ssh.FingerprintSHA256(pub), nil
}

// sshSignature is the SSHSIG blob (PROTOCOL.sshsig in OpenSSH).
type sshSignature struct {
	Version       uint32
	PublicKey     []byte
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     []byte
}

// VerifySSH reports whether armoredSig, an SSHSIG signature in namespace
// SSHNamespace, signs challenge with authorizedKey.
func VerifySSH(authorizedKey, armoredSig, challenge string) (bool, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return false, err
	}

	block, _ := pem.Decode([]byte(strings.TrimSpace(armoredSig)))
	if block == nil || block.Type != "SSH SIGNATURE" || !bytes.HasPrefix(block.Bytes, []byte("SSHSIG")) {
		return false, nil
	}
	var sig sshSignature
	if err := ssh.Unmarshal(block.Bytes[len("SSHSIG"):], &sig); err != nil {
		return false, nil
	}
	if sig.Version != 1 || sig.Namespace != SSHNamespace || !bytes.Equal(sig.PublicKey, pub.Marshal()) {
		return false, nil
	}

	var newHash func() hash.Hash
	switch sig.HashAlgorithm {
	case "sha256":
		newHash = sha256.New
	case "sha512":
		newHash = sha512.New
	default:
		return false, nil
	}
	var inner ssh.Signature
	if err := ssh.Unmarshal(sig.Signature, &inner); err != nil {
		return false, nil
	}

	// The signed file may end with the newline `echo` adds.
	for _, message := range []string{challenge, challenge + "\n"} {
		h := newHash()
		h.Write([]byte(message))
		signed := append([]byte("SSHSIG"), ssh.Marshal(struct {
			Namespace     string
			Reserved      string
			HashAlgorithm string
			Hash          []byte
		}{sig.Namespace, sig.Reserved, sig.HashAlgorithm, h.Sum(nil)})...)
		if pub.Verify(signed, &inner) == nil {
			return true, nil
		}
	}
	return false, nil
}

// sameText compares a signed text with the challenge, ignoring the line ending
// and surrounding whitespace a signing tool may add.
func sameText(signed, challenge string) bool {
	return strings.TrimSpace(strings.ReplaceAll(signed, "\r\n", "\n")) == strings.TrimSpace(challenge)
}
