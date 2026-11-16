// Package providers wires the notification providers built into core.
//
// Importing this package (for its side effects) registers them. Core code
// blank-imports it exactly once (from pkg/app).
//
// The built-in "generic" provider (SMTP email rendered from the templates in
// pkg/notify/templates) is registered unconditionally, so the default build is
// self-contained.
//
// # Vendor providers
//
// A distribution module (a Go module with its own main package, see pkg/ext)
// adds a vendor provider: it implements notify.Provider, calls
// notify.Register from init(), and blank-imports that package next to
// cmd/meiling/cli in its main. The provider is then selectable by name
// through notification.defaultProvider or notification.keys, and can keep its
// own settings with config.RegisterSection. Core never needs to change, and its
// go.mod never picks up the vendor's dependencies.
package providers

import (
	// Register the built-in "generic" notification provider (SMTP email).
	// This provider is always enabled so the default build is self-contained.
	_ "github.com/meili-NG/meiliNG/v2/pkg/notify/providers/generic"
)
