package utils

import "encoding/base64"

func Base64Encode(data []byte) string {
	encoder := base64.StdEncoding
	return encoder.EncodeToString(data)
}
