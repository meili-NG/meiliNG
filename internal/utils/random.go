package utils

import (
	"crypto/rand"
	"math/big"
)

func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return RandomStringWithCharset(length, charset)
}

func RandomStringWithCharset(length int, charset string) string {
	return randomString(length, charset)
}

func randomString(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		number, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			// These strings are secrets, so there is no weaker source to fall back on.
			panic("utils: crypto/rand failed: " + err.Error())
		}

		b[i] = charset[number.Int64()]
	}
	return string(b)
}
