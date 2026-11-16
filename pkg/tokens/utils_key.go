package tokens

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"os"
	"runtime"
)

// keyFileMode is the mode new key files get. An existing file keeps its own.
const keyFileMode = 0o600

// createKeyFile opens path for writing, creating it with keyFileMode.
func createKeyFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, keyFileMode)
}

// warnUnsafePermissions logs when a private key file is accessible to the
// group or other users. It only warns: the operator owns the file's mode.
func warnUnsafePermissions(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		log.Printf("warning: unsafe permission %#o on private key %s; restrict it to %#o", info.Mode().Perm(), path, keyFileMode)
	}
}

func loadPEM(path string) ([]byte, error) {
	privateKeyFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer privateKeyFile.Close()

	privateKeyBytes, err := io.ReadAll(privateKeyFile)
	if err != nil {
		panic(err)
	}

	privateKeyPEM, _ := pem.Decode(privateKeyBytes)
	if privateKeyPEM == nil {
		panic("Error while decoding private key located at " + path)
	}
	return privateKeyPEM.Bytes, nil
}

func loadRSAPrivateKey(path string) *rsa.PrivateKey {
	warnUnsafePermissions(path)
	privateKeyPEM, err := loadPEM(path)
	if err != nil {
		panic(err)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyPEM)
	if err != nil {
		// try parsing as PKCS1
		privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyPEM)
		if err != nil {
			panic(err)
		}

		// resave as PKCS8
		serialized, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err == nil {
			privateKeyPEM := &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: serialized,
			}
			_ = savePEM(path, privateKeyPEM)
		}
	}

	if privateKey, ok := privateKey.(*rsa.PrivateKey); ok {
		return privateKey
	}

	panic("Invalid private key type")
}

func loadRSAPublicKey(path string) *rsa.PublicKey {
	publicKeyPEM, err := loadPEM(path)
	if err != nil {
		panic(err)
	}

	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyPEM)
	if err == nil {
		return publicKey
	}

	genericPublicKey, parsePKIXErr := x509.ParsePKIXPublicKey(publicKeyPEM)
	if parsePKIXErr != nil {
		panic(err)
	}

	rsaPublicKey, ok := genericPublicKey.(*rsa.PublicKey)
	if !ok {
		panic("Invalid public key type")
	}

	return rsaPublicKey
}

func savePEM(path string, block *pem.Block) error {
	privateKeyFile, err := createKeyFile(path)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	if err := pem.Encode(privateKeyFile, block); err != nil {
		return err
	}

	return nil
}

func tryLoadRSAPublicKey(path string, privateKey *rsa.PrivateKey) *rsa.PublicKey {
	if _, err := os.Stat(path); os.IsNotExist(err) || path == "" {
		if path != "" {
			// save public key
			publicKeyPEM := &pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
			}

			_ = savePEM(path, publicKeyPEM)
		} else if privateKey != nil {
			return &privateKey.PublicKey
		} else {
			return nil
		}
	}

	publicKey := loadRSAPublicKey(path)

	// check if public key matches the private key
	if publicKey.N.Cmp(privateKey.N) != 0 {
		panic("Public key does not match the private key")
	}

	return publicKey
}

func loadECDSAPrivateKey(path string) *ecdsa.PrivateKey {
	warnUnsafePermissions(path)
	privateKeyPEM, err := loadPEM(path)
	if err != nil {
		panic(err)
	}

	privateKey, err := x509.ParseECPrivateKey(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	return privateKey
}

func tryLoadECDSAPublicKey(path string, privateKey *ecdsa.PrivateKey) *ecdsa.PublicKey {
	if _, err := os.Stat(path); os.IsNotExist(err) || path == "" {
		if path != "" {
			// save public key
			publicKeyPEM, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
			if err != nil {
				panic(err)
			}

			publicKeyBlock := &pem.Block{
				Type:  "ECDSA PUBLIC KEY",
				Bytes: publicKeyPEM,
			}

			_ = savePEM(path, publicKeyBlock)
		} else if privateKey != nil {
			return &privateKey.PublicKey
		} else {
			return nil
		}
	}

	ecdsaPublicKey := loadECDSAPublicKey(path)

	// check if public key matches the private key
	if ecdsaPublicKey.X.Cmp(privateKey.X) != 0 || ecdsaPublicKey.Y.Cmp(privateKey.Y) != 0 {
		panic("Public key does not match the private key")
	}

	return ecdsaPublicKey
}

func loadECDSAPublicKey(path string) *ecdsa.PublicKey {
	publicKeyPEM, err := loadPEM(path)
	if err != nil {
		panic(err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyPEM)
	if err != nil {
		panic(err)
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		panic("Invalid public key type")
	}

	return ecdsaPublicKey
}

func generateRSAKey(privateKeyPath string) error {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Save private key to file
	privateKeyFile, err := createKeyFile(privateKeyPath)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	serialized, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	privateKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: serialized,
	}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	return nil
}
