package errors

// Config holds error-related configuration.
type Config struct {
	Debug             bool
	RespondStackTrace bool
}

var globalConfig *Config

// SetConfig sets the global configuration for the errors package.
func SetConfig(cfg *Config) {
	globalConfig = cfg
}

// GetConfig returns the global configuration.
func GetConfig() *Config {
	return globalConfig
}

func isDebugMode() bool {
	return globalConfig != nil && globalConfig.Debug
}

func shouldRespondWithStacktrace() bool {
	return globalConfig != nil && globalConfig.Debug && globalConfig.RespondStackTrace
}
