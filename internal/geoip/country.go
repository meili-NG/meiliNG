package geoip

import (
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

func NormalizeCountryCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	region, err := language.ParseRegion(value)
	if err != nil {
		return ""
	}

	return region.Canonicalize().String()
}

func CountryName(code string) string {
	code = NormalizeCountryCode(code)
	if code == "" {
		return ""
	}

	region, err := language.ParseRegion(code)
	if err != nil {
		return ""
	}

	name := strings.TrimSpace(display.English.Regions().Name(region))
	if name == "" {
		return code
	}

	return name
}

func CountryCodeFromData(data map[string]any) string {
	if len(data) == 0 {
		return ""
	}

	for _, key := range []string{"countryCode", "registeredCountryCode"} {
		if value, ok := data[key]; ok {
			if code := NormalizeCountryCode(stringValue(value)); code != "" {
				return code
			}
		}
	}

	if raw, ok := nestedMap(data["country"]); ok {
		if code := NormalizeCountryCode(stringValue(raw["iso_code"])); code != "" {
			return code
		}
	}

	if raw, ok := nestedMap(data["registered_country"]); ok {
		if code := NormalizeCountryCode(stringValue(raw["iso_code"])); code != "" {
			return code
		}
	}

	return ""
}

func CountryNameFromData(data map[string]any) string {
	if len(data) == 0 {
		return ""
	}

	for _, key := range []string{"country", "registeredCountry"} {
		if name := strings.TrimSpace(stringValue(data[key])); name != "" {
			return name
		}
	}

	if raw, ok := nestedMap(data["country"]); ok {
		if name := nestedCountryName(raw); name != "" {
			return name
		}
	}

	if raw, ok := nestedMap(data["registered_country"]); ok {
		if name := nestedCountryName(raw); name != "" {
			return name
		}
	}

	return ""
}

func nestedCountryName(raw map[string]any) string {
	names, _ := nestedMap(raw["names"])
	return strings.TrimSpace(stringValue(names["en"]))
}

func nestedMap(value any) (map[string]any, bool) {
	raw, ok := value.(map[string]any)
	return raw, ok
}

func stringValue(value any) string {
	str, ok := value.(string)
	if !ok {
		return ""
	}
	return str
}
