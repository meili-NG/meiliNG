//go:build !nowebui

// Package ui holds the production Vite build that Meiling embeds into the
// server binary. go:embed cannot walk out of this directory, so the built
// files live here (ui/dist) rather than under pkg/server/webui.
package ui

import "embed"

// Dist is the Vite production output (index.html and hashed assets).
// Rebuild with: go generate ./ui
// Build with -tags nowebui to leave it out of the binary.
//
//go:generate npm ci
//go:generate npm run build
//go:embed all:dist
var Dist embed.FS
