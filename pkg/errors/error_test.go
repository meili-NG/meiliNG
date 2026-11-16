package errors

import (
	"encoding/json"
	stdErrors "errors"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func withErrorConfig(t *testing.T, cfg *Config) {
	t.Helper()

	previous := GetConfig()
	SetConfig(cfg)
	t.Cleanup(func() {
		SetConfig(previous)
	})
}

func TestNewAndWrap(t *testing.T) {
	withErrorConfig(t, &Config{})

	err := New(ErrInvalidRequest, "bad request")
	if err.Error() != "invalid_request: bad request" {
		t.Fatalf("Error() = %q", err.Error())
	}
	if err.GetStatus() != fiber.StatusBadRequest {
		t.Fatalf("GetStatus() = %d", err.GetStatus())
	}

	cause := stdErrors.New("root cause")
	wrapped := Wrap(ErrUnauthorized, "failed to load", cause)
	if wrapped.Cause() != cause || wrapped.Unwrap() != cause {
		t.Fatalf("Wrap should preserve the underlying cause")
	}
	if wrapped.Message != "failed to load" {
		t.Fatalf("Wrap should keep its own message, got %q", wrapped.Message)
	}
	if wrapped.Error() != "unauthorized: failed to load: root cause" {
		t.Fatalf("wrapped Error() = %q", wrapped.Error())
	}
}

// The cause can carry SQL or driver details, so only debug mode sends it.
func TestCauseReachesTheResponseOnlyInDebug(t *testing.T) {
	cause := stdErrors.New(`pq: relation "users" does not exist`)

	withErrorConfig(t, &Config{})
	if got := InternalServerError("failed to find user", cause).ToJSON()["message"]; got != "failed to find user" {
		t.Fatalf("production message = %q, want only the safe message", got)
	}
	if got := Wrap(ErrInvalidGrant, "", cause).SetOAuth2(true).ToJSON()["error_description"]; got != "" {
		t.Fatalf("production error_description = %q, want empty", got)
	}

	withErrorConfig(t, &Config{Debug: true})
	if got := InternalServerError("failed to find user", cause).ToJSON()["message"]; got != `failed to find user: pq: relation "users" does not exist` {
		t.Fatalf("debug message = %q, want the cause appended", got)
	}
}

func TestOAuth2JSON(t *testing.T) {
	withErrorConfig(t, &Config{})

	err := NewOAuth2(ErrInvalidClient, "bad client")
	payload := err.ToJSON()

	if payload["error"] != ErrInvalidClient {
		t.Fatalf("oauth2 error type = %#v", payload["error"])
	}
	if payload["error_description"] != "bad client" {
		t.Fatalf("oauth2 error description = %#v", payload["error_description"])
	}
	if payload["url"] != "https://tools.ietf.org/html/rfc6749#section-5.2" {
		t.Fatalf("oauth2 url = %#v", payload["url"])
	}
	if !err.IsOAuth2() {
		t.Fatalf("NewOAuth2 should mark the error as OAuth2")
	}
}

func TestToJSONIncludesStacktraceWhenConfigured(t *testing.T) {
	withErrorConfig(t, &Config{
		Debug:             true,
		RespondStackTrace: true,
	})

	payload := New(ErrUnhandledInternalServerError, "internal failure").ToJSON()
	stacktrace, ok := payload["stacktrace"].(string)
	if !ok || stacktrace == "" {
		t.Fatalf("expected stacktrace in response payload: %#v", payload)
	}
}

func TestMarshalJSON(t *testing.T) {
	withErrorConfig(t, &Config{})

	raw, err := New(ErrNotFound, "missing").MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if payload["type"] != string(ErrNotFound) || payload["message"] != "missing" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestFromFiberError(t *testing.T) {
	notFound := FromFiberError(fiber.NewError(fiber.StatusNotFound, "missing"))
	if notFound == nil || notFound.Type != ErrNotFound {
		t.Fatalf("FromFiberError(not found) = %#v", notFound)
	}

	methodNotAllowed := FromFiberError(fiber.NewError(fiber.StatusMethodNotAllowed, "method not allowed"))
	if methodNotAllowed == nil || methodNotAllowed.Type != ErrMethodNotAllowed {
		t.Fatalf("FromFiberError(method not allowed) = %#v", methodNotAllowed)
	}

	if got := FromFiberError(fiber.NewError(fiber.StatusBadGateway, "bad gateway")); got != nil {
		t.Fatalf("FromFiberError should return nil for unmapped errors, got %#v", got)
	}
}

func TestRespond(t *testing.T) {
	withErrorConfig(t, &Config{})

	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		return Respond(c, New(ErrNotFound, "missing"))
	})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusNotFound)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if payload["type"] != string(ErrNotFound) || payload["message"] != "missing" {
		t.Fatalf("payload = %#v", payload)
	}
}
