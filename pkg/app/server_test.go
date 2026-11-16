package app

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestSkipRequestLog(t *testing.T) {
	app := fiber.New()
	wantSkipped := map[string]bool{
		"/health": true,
		"/":       false,
	}

	app.Use(func(c *fiber.Ctx) error {
		if got := skipRequestLog(c); got != wantSkipped[c.Path()] {
			t.Fatalf("skipRequestLog(%q) = %v", c.Path(), got)
		}
		return c.SendStatus(fiber.StatusNoContent)
	})

	for path := range wantSkipped {
		req := httptest.NewRequest("GET", path, nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test(%q): %v", path, err)
		}
		resp.Body.Close()
	}
}
