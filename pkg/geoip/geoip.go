// Package geoip resolves where a sign-in came from. The built-in lookup reads
// a MaxMind-format database (see MMDB) and is off until one is configured; a
// distribution can supply another lookup through Provider.
//
// Lookup order for each request IP:
//
//  1. A resolver set on the instance with Meiling.SetGeoIPResolver.
//  2. The resolver Provider built for the instance at startup.
package geoip

import (
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
)

// Result is the location stored with a sign-in log.
type Result struct {
	Country     string
	CountryCode string
	// Data is the full provider record, stored as JSON for later queries.
	Data map[string]any
}

// ResolveFunc resolves an IP address. Returning nil, nil means the location is
// unknown, which is not an error.
type ResolveFunc func(ip string) (*Result, error)

// ProviderFunc builds the lookup for an instance from its config, so a
// provider can read its own config section. Returning a nil ResolveFunc leaves
// GeoIP off for that instance; an error fails startup.
type ProviderFunc func(cfg *config.MeilingConfig) (ResolveFunc, error)

// Provider supplies the GeoIP lookup. It defaults to MMDB; a distribution
// replaces it to use another lookup:
//
//	func init() { geoip.Provider.Override(myProvider) }
var Provider = ext.NewSlot[ProviderFunc](MMDB)
