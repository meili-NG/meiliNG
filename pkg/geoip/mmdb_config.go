package geoip

import (
	"strings"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// SectionPath is where Config, the settings of the built-in MMDB lookup, is
// read from.
const SectionPath = "geoip"

// Config locates the MaxMind-format database (.mmdb) of the built-in lookup.
// Any vendor's MMDB works: MaxMind GeoIP2/GeoLite2, DB-IP, IPinfo and the
// like.
type Config struct {
	// MMDBPath is the database file. Empty turns the built-in lookup off.
	MMDBPath string `json:"mmdbPath"`
}

func init() {
	config.RegisterSection[Config](SectionPath)
}

// MMDB is Provider's default. It resolves from the database in Config, and
// leaves GeoIP off when geoip.mmdbPath is unset.
func MMDB(cfg *config.MeilingConfig) (ResolveFunc, error) {
	c, _ := config.Section[Config](cfg, SectionPath)
	if strings.TrimSpace(c.MMDBPath) == "" {
		return nil, nil
	}
	return NewMMDBResolver(c.MMDBPath).Resolve, nil
}
