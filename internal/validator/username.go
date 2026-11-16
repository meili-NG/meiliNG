package validator

import (
	"net/mail"
	"strings"

	"github.com/meili-NG/meiliNG/v2/internal/utils"
)

// IsValidUsername checks if a username is valid
func IsValidUsername(username string) bool {
	// mail address can not be a valid username
	if _, err := mail.ParseAddress(username); err == nil {
		return false
	}

	// the username should not be a blank
	if strings.TrimSpace(username) == "" {
		return false
	}

	// the username should be consisting of only alphanumeric characters
	if !utils.IsAlphanumeric(username) {
		return false
	}

	return true
}
