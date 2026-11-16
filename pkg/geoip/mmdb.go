package geoip

import (
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// mmdbRecheck is how often the file is looked at again: to retry after a
// failed open, and to pick up a replaced database.
const mmdbRecheck = time.Minute

type MMDBResolver struct {
	path string

	// mu guards reader for lookups (read) and for swapping it (write).
	mu      sync.RWMutex
	reader  *maxminddb.Reader
	modTime time.Time
	err     error
	// nextCheck is the unix nano time after which the file is checked again.
	nextCheck atomic.Int64
}

type mmdbNames struct {
	English string `maxminddb:"en"`
}

type mmdbCountryRecord struct {
	ISOCode string    `maxminddb:"iso_code"`
	Names   mmdbNames `maxminddb:"names"`
}

type mmdbLocationRecord struct {
	Country           mmdbCountryRecord `maxminddb:"country"`
	RegisteredCountry mmdbCountryRecord `maxminddb:"registered_country"`
}

// NewMMDBResolver reads the MMDB at path. Keeping that file present and
// current is the operator's job, for example with MaxMind's geoipupdate.
func NewMMDBResolver(path string) *MMDBResolver {
	return &MMDBResolver{path: path}
}

func (r *MMDBResolver) Resolve(ip string) (*Result, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.IsValid() {
		return nil, nil
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() {
		return nil, nil
	}

	r.refresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.reader == nil {
		return nil, r.err
	}

	lookup := r.reader.Lookup(addr)

	var record mmdbLocationRecord
	if err := lookup.Decode(&record); err == nil {
		return buildGeoIPResult(record), nil
	}

	var raw map[string]any
	if err := lookup.Decode(&raw); err != nil {
		return nil, err
	}

	return buildGeoIPResultFromRaw(raw), nil
}

// refresh opens the file when none is open yet or it changed on disk, at most
// once per mmdbRecheck. A failed attempt keeps the reader already open.
func (r *MMDBResolver) refresh() {
	now := time.Now().UnixNano()
	if next := r.nextCheck.Load(); now < next || !r.nextCheck.CompareAndSwap(next, now+int64(mmdbRecheck)) {
		return
	}

	info, err := os.Stat(r.path)
	if err == nil && r.hasOpen(info.ModTime()) {
		return
	}
	var reader *maxminddb.Reader
	if err == nil {
		reader, err = maxminddb.Open(r.path)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		if r.reader == nil {
			r.err = err
		}
		return
	}
	if r.reader != nil {
		_ = r.reader.Close()
	}
	r.reader, r.modTime, r.err = reader, info.ModTime(), nil
}

func (r *MMDBResolver) hasOpen(modTime time.Time) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.reader != nil && r.modTime.Equal(modTime)
}

func formatCountry(record mmdbLocationRecord) string {
	countryName := strings.TrimSpace(record.Country.Names.English)
	if countryName == "" {
		countryName = strings.TrimSpace(record.RegisteredCountry.Names.English)
	}
	if countryName != "" {
		return countryName
	}

	countryCode := strings.TrimSpace(record.Country.ISOCode)
	if countryCode == "" {
		countryCode = strings.TrimSpace(record.RegisteredCountry.ISOCode)
	}

	return countryCode
}

func buildGeoIPResult(record mmdbLocationRecord) *Result {
	data := map[string]any{}
	countryCode := strings.TrimSpace(record.Country.ISOCode)
	if countryCode == "" {
		countryCode = strings.TrimSpace(record.RegisteredCountry.ISOCode)
	}

	if country := strings.TrimSpace(record.Country.Names.English); country != "" {
		data["country"] = country
	}
	if countryCode != "" {
		data["countryCode"] = countryCode
	}
	if registeredCountry := strings.TrimSpace(record.RegisteredCountry.Names.English); registeredCountry != "" {
		data["registeredCountry"] = registeredCountry
	}
	if registeredCountryCode := strings.TrimSpace(record.RegisteredCountry.ISOCode); registeredCountryCode != "" {
		data["registeredCountryCode"] = registeredCountryCode
	}

	return &Result{
		Country:     formatCountry(record),
		CountryCode: countryCode,
		Data:        data,
	}
}

func buildGeoIPResultFromRaw(raw map[string]any) *Result {
	if len(raw) == 0 {
		return nil
	}

	data := map[string]any{}

	country := extractCountryName(raw, "country")
	countryCode := extractCountryCode(raw, "country")
	if countryCode == "" {
		countryCode = extractString(raw, "country_code")
	}

	registeredCountry := extractCountryName(raw, "registered_country")
	registeredCountryCode := extractCountryCode(raw, "registered_country")
	if registeredCountryCode == "" {
		registeredCountryCode = extractString(raw, "registered_country_code")
	}

	if country != "" {
		data["country"] = country
	}
	if countryCode != "" {
		data["countryCode"] = countryCode
	}
	if registeredCountry != "" {
		data["registeredCountry"] = registeredCountry
	}
	if registeredCountryCode != "" {
		data["registeredCountryCode"] = registeredCountryCode
	}

	if country == "" {
		country = registeredCountry
	}
	if country == "" {
		country = countryCode
	}
	if country == "" {
		country = registeredCountryCode
	}

	if country == "" && countryCode == "" && len(data) == 0 {
		return nil
	}

	return &Result{
		Country:     country,
		CountryCode: countryCode,
		Data:        data,
	}
}

func extractCountryName(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}

		switch v := value.(type) {
		case string:
			if name := strings.TrimSpace(v); name != "" {
				return name
			}
		case map[string]any:
			if name := extractEnglishName(v); name != "" {
				return name
			}
		}
	}

	return ""
}

func extractCountryCode(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}

		if nested, ok := value.(map[string]any); ok {
			if code := extractString(nested, "iso_code"); code != "" {
				return code
			}
		}
	}

	return ""
}

func extractEnglishName(raw map[string]any) string {
	names, _ := raw["names"].(map[string]any)
	return extractString(names, "en")
}

func extractString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}

		if str, ok := value.(string); ok {
			if trimmed := strings.TrimSpace(str); trimmed != "" {
				return trimmed
			}
		}
	}

	return ""
}
