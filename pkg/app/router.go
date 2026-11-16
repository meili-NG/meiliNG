package app

import "github.com/gofiber/fiber/v2"

// Router interface to avoid import cycle with routes package
type Router interface {
	Register() error
}

// RouterFactory creates a router instance
type RouterFactory func(fiberApp *fiber.App, m *Meiling, name string) Router

// Global router factory - set by routes package
var routerFactory RouterFactory

// SetRouterFactory sets the router factory function
func SetRouterFactory(factory RouterFactory) {
	routerFactory = factory
}
