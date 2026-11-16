package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	koanfjson "github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/v2"
	pkgconfig "github.com/meili-NG/meiliNG/v2/pkg/config"
)

const (
	configFileName        = "config.json"
	maxConfigSearchLevels = 5
)

// configFileNames are the config file names searched for, in order of
// preference, in each candidate directory.
var configFileNames = []string{"config.json", "config.yaml", "config.yml", "config.toml"}

// SystemConfigPath returns the config file in the system config directory
// (config.ConfigDir, e.g. /etc/meiling), or "" when there is none. It is the
// base layer a local config file overrides. Windows has no system layer.
func SystemConfigPath() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return findConfigFileIn(pkgconfig.ConfigDir())
}

// findConfigFileIn returns the first config file present in dir.
func findConfigFileIn(dir string) string {
	for _, name := range configFileNames {
		configPath := filepath.Join(dir, name)
		if info, err := os.Stat(configPath); err == nil && !info.IsDir() {
			return configPath
		}
	}
	return ""
}

// FindConfigPath returns the local config file: the first one found in the
// working directory or up to maxConfigSearchLevels of its parents. It does not
// return the system config file, which SystemConfigPath covers.
func FindConfigPath() (string, error) {
	cwd, err := os.Getwd()
	if err == nil {
		currentDir := cwd
		for i := 0; i < maxConfigSearchLevels; i++ {
			if configPath := findConfigFileIn(currentDir); configPath != "" {
				return configPath, nil
			}

			parentDir := filepath.Dir(currentDir)
			if parentDir == currentDir {
				break
			}
			currentDir = parentDir
		}
	}

	// No local config file: the system file and environment variables apply.
	return "", nil
}

type configParser interface {
	Unmarshal([]byte) (map[string]any, error)
	Marshal(map[string]any) ([]byte, error)
}

// parserFor picks the parser from the file extension. Unknown extensions are
// read as JSON.
func parserFor(path string) configParser {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return yaml.Parser()
	case ".toml":
		return toml.Parser()
	default:
		return koanfjson.Parser()
	}
}

// resolveConfigFile turns a file or directory path into a config file path.
func resolveConfigFile(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return absPath, nil
	}

	if configPath := findConfigFileIn(absPath); configPath != "" {
		return configPath, nil
	}
	return "", fmt.Errorf("no config file (%s) in %s: %w", strings.Join(configFileNames, ", "), absPath, os.ErrNotExist)
}

// sameFile reports whether a and b name the same existing file.
func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}

// readConfigFile parses a config file into a map with canonical keys.
func readConfigFile(schema *configSchema, path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	data, err := parserFor(path).Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}

	return schema.canonicalize(data, ""), nil
}

// LoadConfigFromFile loads configuration from a JSON, YAML or TOML file alone,
// without defaults or environment variables.
func LoadConfigFromFile(path string) (*pkgconfig.MeilingConfig, error) {
	schema, err := newSchema()
	if err != nil {
		return nil, err
	}

	data, err := readConfigFile(schema, path)
	if err != nil {
		return nil, err
	}

	k := koanf.New(".")
	if err := k.Load(confmap.Provider(data, ""), nil); err != nil {
		return nil, err
	}
	return decode(k)
}

// LoadConfigFromPath loads configuration from a specific path (file or directory)
func LoadConfigFromPath(path string) (*pkgconfig.MeilingConfig, error) {
	configPath, err := resolveConfigFile(path)
	if err != nil {
		return nil, err
	}

	return LoadConfigFromFile(configPath)
}

// LoadConfig loads configuration, each layer overriding the previous one:
//  1. `default` struct tags
//  2. Distribution defaults registered with config.SetDefault
//  3. The system config file in config.ConfigDir (SystemConfigPath), if any
//  4. The local config file (JSON, YAML or TOML): the given path, or else the
//     one FindConfigPath finds, if any
//  5. Environment variables (e.g. MEILING_OAUTH2__ALLOW_CREATE)
func LoadConfig() (*pkgconfig.MeilingConfig, error) {
	return LoadConfigWithPath("")
}

// LoadConfigWithPath loads configuration from a specific path or auto-discovers
func LoadConfigWithPath(configPath string) (*pkgconfig.MeilingConfig, error) {
	return loadConfig(configPath, os.Environ)
}

func loadConfig(configPath string, environ func() []string) (*pkgconfig.MeilingConfig, error) {
	// If no path specified, try to find config file
	if configPath == "" {
		foundPath, err := FindConfigPath()
		if err == nil && foundPath != "" {
			configPath = foundPath
		}
	}

	schema, err := newSchema()
	if err != nil {
		return nil, err
	}

	systemPath := SystemConfigPath()
	var system, local map[string]any
	if systemPath != "" {
		if system, err = readConfigFile(schema, systemPath); err != nil {
			return nil, err
		}
	}
	if configPath != "" {
		resolved, err := resolveConfigFile(configPath)
		if err != nil {
			return nil, err
		}
		if !sameFile(resolved, systemPath) {
			if local, err = readConfigFile(schema, resolved); err != nil {
				return nil, err
			}
		}
	}

	distribution, err := schema.distributionDefaults()
	if err != nil {
		return nil, err
	}

	k := koanf.New(".")
	for _, layer := range []map[string]any{schema.defaults(), distribution, system, local} {
		if err := k.Load(confmap.Provider(layer, ""), nil); err != nil {
			return nil, err
		}
	}

	if err := k.Load(env.Provider(".", env.Opt{
		Prefix:        pkgconfig.EnvPrefix(),
		TransformFunc: schema.structuredEnvTransform,
		EnvironFunc:   environ,
	}), nil); err != nil {
		return nil, err
	}

	cfg, err := decode(k)
	if err != nil {
		return nil, err
	}

	// Post-process the configuration
	if err := cfg.PostProcess(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// decode unmarshals the merged layers into a MeilingConfig, then each
// registered section into its own struct.
func decode(k *koanf.Koanf) (*pkgconfig.MeilingConfig, error) {
	var cfg pkgconfig.MeilingConfig
	if err := unmarshal(k, "", &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	for _, section := range pkgconfig.RegisteredSections() {
		value := reflect.New(section.Type)
		if err := unmarshal(k, section.Path, value.Interface()); err != nil {
			return nil, fmt.Errorf("decode config section %s: %w", section.Path, err)
		}
		cfg.SetSection(section.Path, value.Elem().Interface())
	}

	return &cfg, nil
}

func unmarshal(k *koanf.Koanf, path string, out any) error {
	return k.UnmarshalWithConf(path, out, koanf.UnmarshalConf{
		Tag: keyTag,
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToSliceHookFunc(","),
			),
			WeaklyTypedInput: true,
		},
	})
}

// SaveConfig writes configuration to a file, in the format its extension names
func SaveConfig(cfg *pkgconfig.MeilingConfig, path string) error {
	if path == "" {
		return errors.New("config path is required")
	}

	// Every format is written from the JSON form, so keys are spelled the same
	// everywhere and registered sections land at their paths.
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	for sectionPath, value := range cfg.Sections {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		var section map[string]any
		if err := json.Unmarshal(raw, &section); err != nil {
			return err
		}
		setPath(data, strings.Split(sectionPath, "."), section)
	}

	var encoded []byte
	if _, isJSON := parserFor(path).(*koanfjson.JSON); isJSON {
		encoded, err = json.MarshalIndent(data, "", "  ")
	} else {
		encoded, err = parserFor(path).Marshal(data)
	}
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 0600 because the file can hold secrets; an existing file keeps its mode.
	return os.WriteFile(path, encoded, 0o600)
}
