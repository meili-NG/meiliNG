package notify

import (
	"fmt"
	"sort"
	"sync"
)

// registry holds all providers registered in the current binary, keyed by name.
var (
	registryMu sync.RWMutex
	registry   = map[string]Provider{}
)

// Register makes a provider available for selection by name.
//
// It is intended to be called from a provider package's init function so that
// blank-importing the package is enough to enable it. Register panics if p is
// nil, has an empty name, or if a provider with the same name was already
// registered, since these all indicate a programming error at wiring time.
func Register(p Provider) {
	if p == nil {
		panic("notify: Register called with nil provider")
	}

	name := p.Name()
	if name == "" {
		panic("notify: Register called with provider that has an empty name")
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("notify: provider %q registered twice", name))
	}

	registry[name] = p
}

// Lookup returns the provider registered under name.
func Lookup(name string) (Provider, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	p, ok := registry[name]
	return p, ok
}

// Providers returns the names of all registered providers, sorted.
func Providers() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
