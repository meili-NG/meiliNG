package notify

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// GenericProviderName is the built-in provider that ships with Meiling. It is
// used as the fallback when a key has no explicit provider configured.
const GenericProviderName = "generic"

// ResolveProvider returns the provider that should handle the given key based
// on cfg.NotificationConfig, falling back to the generic provider.
//
// Resolution order:
//  1. An explicit per-key mapping in NotificationConfig.Keys.
//  2. NotificationConfig.DefaultProvider, if set.
//  3. The built-in generic provider.
func ResolveProvider(cfg *config.MeilingConfig, key NotifyKey) (Provider, error) {
	name := GenericProviderName

	if cfg != nil {
		nc := cfg.NotificationConfig
		if mapped, ok := nc.Keys[string(key)]; ok && mapped != "" {
			name = mapped
		} else if nc.DefaultProvider != "" {
			name = nc.DefaultProvider
		}
	}

	p, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("notify: no provider registered under %q (registered: %v)", name, Providers())
	}

	if !p.Supports(key) {
		return nil, fmt.Errorf("notify: provider %q does not support key %q", name, key)
	}

	return p, nil
}

// Dispatch resolves the provider for n.Key and delivers the notification.
func Dispatch(ctx context.Context, cfg *config.MeilingConfig, n Notification) error {
	p, err := ResolveProvider(cfg, n.Key)
	if err != nil {
		return err
	}

	if cfg != nil && cfg.DebugConfig.Enabled {
		log.Printf("notify: dispatching key=%q via provider=%q", n.Key, p.Name())
	}

	return p.Notify(ctx, cfg, n)
}

// LogResolution prints, once at startup, which providers are compiled into this
// build and how each known key resolves given the active configuration. This is
// the single place to confirm whether a deployment is using the generic or a
// vendor provider without sending a notification.
func LogResolution(cfg *config.MeilingConfig) {
	defaultProvider := GenericProviderName
	if cfg != nil && cfg.NotificationConfig.DefaultProvider != "" {
		defaultProvider = cfg.NotificationConfig.DefaultProvider
	}

	var b strings.Builder
	fmt.Fprintf(&b, "notify: registered=%v default=%q", Providers(), defaultProvider)
	for _, key := range KnownKeys() {
		if p, err := ResolveProvider(cfg, key); err != nil {
			fmt.Fprintf(&b, " %s->ERROR(%v)", key, err)
		} else {
			fmt.Fprintf(&b, " %s->%q", key, p.Name())
		}
	}

	log.Print(b.String())
}
