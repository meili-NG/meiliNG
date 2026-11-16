package config

import (
	"fmt"
	"sort"
	"sync"
)

// Distribution defaults replace the built-in `default` tag values of config
// keys, so a distribution ships its own out-of-the-box configuration without
// patching core. Register them from init():
//
//	func init() {
//		config.SetDefault("instance.name", "Acme ID")
//		config.SetDefault("server.publicUrl", "https://id.acme.example")
//		config.SetDefault("notification.defaultProvider", "acme")
//	}
//
// They form the layer right above the built-in defaults: config files and
// environment variables still override them, exactly as they override the
// built-in ones. Paths are dotted config keys as written in a config file and
// match as loosely as file keys do; a path that names no setting, including
// registered sections, fails config loading so a typo cannot pass silently.
// A string value is parsed like an environment variable ("true", "2h",
// "a,b" for lists); any other value is used as is.

var (
	defaultsMu sync.RWMutex
	defaults   = map[string]any{}
)

// SetDefault sets the distribution default for the config key at path. A later
// call for the same path replaces the earlier value. It panics on an empty
// path, which is a programming error.
func SetDefault(path string, value any) {
	if path == "" {
		panic("config: SetDefault called with an empty path")
	}
	defaultsMu.Lock()
	defer defaultsMu.Unlock()
	defaults[path] = value
}

// DistributionDefault is one SetDefault registration.
type DistributionDefault struct {
	Path  string
	Value any
}

// DistributionDefaults returns the registered defaults sorted by path.
func DistributionDefaults() []DistributionDefault {
	defaultsMu.RLock()
	defer defaultsMu.RUnlock()

	out := make([]DistributionDefault, 0, len(defaults))
	for path, value := range defaults {
		out = append(out, DistributionDefault{Path: path, Value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// ResetDefaults removes every distribution default. It exists for tests.
func ResetDefaults() {
	defaultsMu.Lock()
	defer defaultsMu.Unlock()
	defaults = map[string]any{}
}

// String implements fmt.Stringer for startup diagnostics.
func (d DistributionDefault) String() string {
	return fmt.Sprintf("%s=%v", d.Path, d.Value)
}
