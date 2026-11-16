//go:build nowebui

package ui

import "embed"

// Dist is empty under the nowebui build tag: the stock web UI is left out of
// the binary and ui/dist does not have to exist. A distribution that ships its
// own build overrides webui.Assets; otherwise webui.path serves one from disk.
var Dist embed.FS
