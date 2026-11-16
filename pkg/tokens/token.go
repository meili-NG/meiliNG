package tokens

import (
	"github.com/gofiber/fiber/v2"
	"strings"
)

func ParseAuthorizationHeader(c *fiber.Ctx) (method string, token string) {
	header := c.Get("Authorization")
	if header == "" {
		return "", ""
	}

	// split the header into two parts
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}

	return parts[0], parts[1]
}
