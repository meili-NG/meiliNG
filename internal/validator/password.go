package validator

// IsValidPassword checks if a password meets minimum requirements
func IsValidPassword(password string) bool {
	return len(password) >= 8
}
