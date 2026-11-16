package utils

import (
	"testing"
)

func TestIsAlphanumeric(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "letters and numbers", input: "abcXYZ123", want: true},
		{name: "empty string", input: "", want: true},
		{name: "contains whitespace", input: "abc 123", want: false},
		{name: "contains punctuation", input: "abc-123", want: false},
	}

	for _, tt := range tests {
		if got := IsAlphanumeric(tt.input); got != tt.want {
			t.Fatalf("%s: IsAlphanumeric(%q) = %v, want %v", tt.name, tt.input, got, tt.want)
		}
	}
}

func TestSearchHelpers(t *testing.T) {
	t.Parallel()

	haystack := []int{1, 2, 2, 3, 4}
	if !Contains(haystack, 3) {
		t.Fatalf("Contains should find existing element")
	}
	if Contains(haystack, 5) {
		t.Fatalf("Contains should not find missing element")
	}

	deduplicated := Deduplicate(haystack)
	wantDeduplicated := []int{1, 2, 3, 4}
	if len(deduplicated) != len(wantDeduplicated) {
		t.Fatalf("Deduplicate length = %d, want %d", len(deduplicated), len(wantDeduplicated))
	}
	for i, want := range wantDeduplicated {
		if deduplicated[i] != want {
			t.Fatalf("Deduplicate[%d] = %d, want %d", i, deduplicated[i], want)
		}
	}

	found, ok := Find(haystack, func(v int) bool { return v > 2 })
	if !ok || found != 3 {
		t.Fatalf("Find returned (%d, %v), want (3, true)", found, ok)
	}

	missing, ok := Find(haystack, func(v int) bool { return v > 10 })
	if ok || missing != 0 {
		t.Fatalf("Find missing returned (%d, %v), want (0, false)", missing, ok)
	}

	filtered := Filter(haystack, func(v int) bool { return v%2 == 0 })
	wantFiltered := []int{2, 2, 4}
	if len(filtered) != len(wantFiltered) {
		t.Fatalf("Filter length = %d, want %d", len(filtered), len(wantFiltered))
	}
	for i, want := range wantFiltered {
		if filtered[i] != want {
			t.Fatalf("Filter[%d] = %d, want %d", i, filtered[i], want)
		}
	}

	if !HasAll([]string{"openid", "profile", "email"}, []string{"profile", "email"}) {
		t.Fatalf("HasAll should succeed when all needles exist")
	}
	if HasAll([]string{"openid"}, []string{"openid", "email"}) {
		t.Fatalf("HasAll should fail when a needle is missing")
	}
}

func TestRepeat(t *testing.T) {
	t.Parallel()

	got := Repeat("x", 3)
	want := []string{"x", "x", "x"}
	if len(got) != len(want) {
		t.Fatalf("Repeat length = %d, want %d", len(got), len(want))
	}
	for i, item := range want {
		if got[i] != item {
			t.Fatalf("Repeat[%d] = %q, want %q", i, got[i], item)
		}
	}
}

func TestEncodingHelpers(t *testing.T) {
	t.Parallel()

	if got := Base64Encode([]byte("hello")); got != "aGVsbG8=" {
		t.Fatalf("Base64Encode = %q, want %q", got, "aGVsbG8=")
	}
}

func TestRandomStringHelpers(t *testing.T) {
	t.Parallel()

	const charset = "abc"
	got := RandomStringWithCharset(64, charset)
	if len(got) != 64 {
		t.Fatalf("RandomStringWithCharset length = %d, want 64", len(got))
	}
	for _, r := range got {
		if !Contains([]rune{'a', 'b', 'c'}, r) {
			t.Fatalf("RandomStringWithCharset returned rune %q outside charset", r)
		}
	}

	random := RandomString(32)
	if len(random) != 32 {
		t.Fatalf("RandomString length = %d, want 32", len(random))
	}
	if !IsAlphanumeric(random) {
		t.Fatalf("RandomString should use the default alphanumeric charset")
	}
}

func TestMergeJSON(t *testing.T) {
	t.Parallel()

	a := map[string]interface{}{
		"keep": "value",
		"nested": map[string]interface{}{
			"left":     "preserved",
			"override": "old",
		},
	}
	b := map[string]interface{}{
		"nested": map[string]interface{}{
			"override": "new",
			"added":    true,
		},
		"new": 123,
	}

	got := MergeJSON(a, b)
	if got["keep"] != "value" {
		t.Fatalf("MergeJSON should preserve existing top-level values")
	}
	if got["new"] != 123 {
		t.Fatalf("MergeJSON should add new top-level values")
	}

	nested, ok := got["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("MergeJSON nested value has unexpected type %T", got["nested"])
	}
	if nested["left"] != "preserved" || nested["override"] != "new" || nested["added"] != true {
		t.Fatalf("MergeJSON nested result = %#v", nested)
	}
}

func TestMergeJSONWithNilBase(t *testing.T) {
	t.Parallel()

	got := MergeJSON(nil, map[string]interface{}{"created": true})
	if got["created"] != true {
		t.Fatalf("MergeJSON should initialize a nil base map when needed")
	}
}
