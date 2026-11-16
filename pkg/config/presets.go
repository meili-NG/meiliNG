package config

// Presets that locate configuration before any config is loaded, so they
// cannot be config keys themselves. A distribution changes them from init().
var (
	envPrefix = "MEILING_"
	configDir = "/etc/meiling"
)

// EnvPrefix is the prefix of structured environment variables:
// MEILING_OAUTH2__ALLOW_CREATE sets oauth2.allowCreate.
func EnvPrefix() string {
	defaultsMu.RLock()
	defer defaultsMu.RUnlock()
	return envPrefix
}

// SetEnvPrefix replaces EnvPrefix. It panics on an empty prefix, which would
// read every environment variable as config.
func SetEnvPrefix(prefix string) {
	if prefix == "" {
		panic("config: SetEnvPrefix called with an empty prefix")
	}
	defaultsMu.Lock()
	defer defaultsMu.Unlock()
	envPrefix = prefix
}

// ConfigDir is the system directory searched for a config file after the
// working directory. It is not used on Windows.
func ConfigDir() string {
	defaultsMu.RLock()
	defer defaultsMu.RUnlock()
	return configDir
}

// SetConfigDir replaces ConfigDir.
func SetConfigDir(dir string) {
	defaultsMu.Lock()
	defer defaultsMu.Unlock()
	configDir = dir
}
