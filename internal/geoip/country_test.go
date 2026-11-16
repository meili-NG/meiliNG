package geoip

import "testing"

func TestNormalizeCountryCode(t *testing.T) {
	t.Parallel()

	if got := NormalizeCountryCode("de"); got != "DE" {
		t.Fatalf("NormalizeCountryCode(de) = %q, want DE", got)
	}
	if got := NormalizeCountryCode("Germany"); got != "" {
		t.Fatalf("NormalizeCountryCode(Germany) = %q, want empty", got)
	}
}

func TestCountryName(t *testing.T) {
	t.Parallel()

	if got := CountryName("KR"); got != "South Korea" {
		t.Fatalf("CountryName(KR) = %q, want South Korea", got)
	}
}

func TestCountryCodeFromData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data map[string]any
		want string
	}{
		{
			name: "flat",
			data: map[string]any{"countryCode": "br"},
			want: "BR",
		},
		{
			name: "nested country",
			data: map[string]any{"country": map[string]any{"iso_code": "US"}},
			want: "US",
		},
		{
			name: "registered country fallback",
			data: map[string]any{"registered_country": map[string]any{"iso_code": "JP"}},
			want: "JP",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := CountryCodeFromData(tc.data); got != tc.want {
				t.Fatalf("CountryCodeFromData() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCountryNameFromData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data map[string]any
		want string
	}{
		{
			name: "flat",
			data: map[string]any{"country": "Canada"},
			want: "Canada",
		},
		{
			name: "nested country",
			data: map[string]any{"country": map[string]any{"names": map[string]any{"en": "United States"}}},
			want: "United States",
		},
		{
			name: "registered country fallback",
			data: map[string]any{"registered_country": map[string]any{"names": map[string]any{"en": "Japan"}}},
			want: "Japan",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := CountryNameFromData(tc.data); got != tc.want {
				t.Fatalf("CountryNameFromData() = %q, want %q", got, tc.want)
			}
		})
	}
}
