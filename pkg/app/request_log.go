package app

import "github.com/gofiber/fiber/v2"

var requestLogSkippedPaths = map[string]struct{}{
	"/health": {},
}

func skipRequestLog(c *fiber.Ctx) bool {
	_, ok := requestLogSkippedPaths[c.Path()]
	return ok
}
