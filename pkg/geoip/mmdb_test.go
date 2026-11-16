package geoip

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestBuildGeoIPResultFromRawFlatRecord(t *testing.T) {
	t.Parallel()

	got := buildGeoIPResultFromRaw(map[string]any{
		"country":                 "Czechia",
		"country_code":            "CZ",
		"registered_country":      "Czech Republic",
		"registered_country_code": "CZ",
	})
	if got == nil {
		t.Fatal("buildGeoIPResultFromRaw() = nil")
	}
	if got.Country != "Czechia" || got.CountryCode != "CZ" {
		t.Fatalf("result country fields = %#v", got)
	}

	wantData := map[string]any{
		"country":               "Czechia",
		"countryCode":           "CZ",
		"registeredCountry":     "Czech Republic",
		"registeredCountryCode": "CZ",
	}
	if !reflect.DeepEqual(got.Data, wantData) {
		t.Fatalf("result data = %#v, want %#v", got.Data, wantData)
	}
}

func TestBuildGeoIPResultFromRawNestedRecord(t *testing.T) {
	t.Parallel()

	got := buildGeoIPResultFromRaw(map[string]any{
		"country": map[string]any{
			"iso_code": "US",
			"names": map[string]any{
				"en": "United States",
			},
		},
		"registered_country": map[string]any{
			"iso_code": "US",
			"names": map[string]any{
				"en": "United States",
			},
		},
	})
	if got == nil {
		t.Fatal("buildGeoIPResultFromRaw() = nil")
	}
	if got.Country != "United States" || got.CountryCode != "US" {
		t.Fatalf("result country fields = %#v", got)
	}
	if got.Data["countryCode"] != "US" {
		t.Fatalf("result data = %#v", got.Data)
	}
}

func TestMMDBIsOffUntilConfigured(t *testing.T) {
	t.Parallel()

	cfg := &config.MeilingConfig{}
	if resolve, err := MMDB(cfg); err != nil || resolve != nil {
		t.Fatalf("MMDB without config = %v, %v; want no resolver", resolve != nil, err)
	}

	cfg.SetSection(SectionPath, Config{MMDBPath: filepath.Join(t.TempDir(), "geo.mmdb")})
	if resolve, err := MMDB(cfg); err != nil || resolve == nil {
		t.Fatalf("MMDB with mmdbPath = %v, %v; want a resolver", resolve != nil, err)
	}
}

// A failed open is retried after mmdbRecheck instead of being kept forever.
func TestMMDBRetriesAFailedOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geo.mmdb")
	r := NewMMDBResolver(path)

	if _, err := r.Resolve("8.8.8.8"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file error = %v, want not-exist", err)
	}

	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("8.8.8.8"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error before the recheck interval = %v, want the cached not-exist", err)
	}

	r.nextCheck.Store(0) // the interval has passed
	if _, err := r.Resolve("8.8.8.8"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error after the recheck = %v, want the new file's parse error", err)
	}
}
