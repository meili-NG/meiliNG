package utils

import (
	"strings"
	"testing"
)

func TestMap(t *testing.T) {
	t.Parallel()

	got := Map([]int{1, 2, 3}, func(v int) string { return strings.Repeat("x", v) })
	want := []string{"x", "xx", "xxx"}
	if len(got) != len(want) {
		t.Fatalf("Map length = %d, want %d", len(got), len(want))
	}
	for i, item := range want {
		if got[i] != item {
			t.Fatalf("Map[%d] = %q, want %q", i, got[i], item)
		}
	}

	if Map[int, string](nil, func(v int) string { return "" }) != nil {
		t.Fatalf("Map should preserve nil input")
	}
}

func TestTransferUpdates(t *testing.T) {
	t.Parallel()

	type source struct {
		Name  string
		Count int
	}
	type target struct {
		Name    string
		Count   int
		Missing string
	}

	dst := target{}
	TransferUpdates(source{Name: "alice", Count: 3}, &dst)

	if dst.Name != "alice" || dst.Count != 3 {
		t.Fatalf("TransferUpdates result = %#v", dst)
	}
	if dst.Missing != "" {
		t.Fatalf("TransferUpdates should ignore unmatched fields")
	}
}

func TestTransferData(t *testing.T) {
	t.Parallel()

	type source struct {
		Name   string
		Age    int
		Active bool
	}
	type target struct {
		Name   string
		Age    string
		Active string
	}

	got := TransferData[source, target](source{Name: "alice", Age: 42, Active: true})
	if got.Name != "alice" || got.Age != "42" || got.Active != "true" {
		t.Fatalf("TransferData result = %#v", got)
	}
}

func TestTransferDataToPointerField(t *testing.T) {
	t.Parallel()

	type source struct {
		Count int
	}
	type target struct {
		Count *int
	}

	src := &source{Count: 7}
	got := TransferData[*source, target](src)
	if got.Count == nil || *got.Count != 7 {
		t.Fatalf("TransferData pointer result = %#v", got)
	}
}

func TestTransferJSONData(t *testing.T) {
	t.Parallel()

	type source struct {
		DisplayName string `json:"name"`
		Count       int    `json:"count"`
		Ignored     string `json:"-"`
	}
	type target struct {
		Name  string `json:"name"`
		Count string `json:"count"`
	}

	got := TransferJSONData[source, target](source{
		DisplayName: "Alice",
		Count:       5,
		Ignored:     "skip",
	})

	if got.Name != "Alice" || got.Count != "5" {
		t.Fatalf("TransferJSONData result = %#v", got)
	}
}

func TestSerializeToMap(t *testing.T) {
	t.Parallel()

	type nested struct {
		Value string `json:"value"`
	}
	type sample struct {
		Name   string `json:"name"`
		Nested nested `json:"nested"`
		Skip   string `json:"-"`
	}

	got := SerializeToMap(sample{
		Name:   "alice",
		Nested: nested{Value: "x"},
		Skip:   "hidden",
	})

	if got["name"] != "alice" {
		t.Fatalf("SerializeToMap name = %#v", got["name"])
	}
	if _, ok := got["skip"]; ok {
		t.Fatalf("SerializeToMap should omit json:\"-\" fields")
	}

	nestedMap, ok := got["nested"].(map[string]any)
	if !ok {
		t.Fatalf("SerializeToMap nested value has type %T", got["nested"])
	}
	if nestedMap["value"] != "x" {
		t.Fatalf("SerializeToMap nested value = %#v", nestedMap)
	}
}

func TestParseDeserialized(t *testing.T) {
	t.Parallel()

	type sample struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	var got sample
	ParseDeserialized(map[string]any{
		"name":  "alice",
		"count": 9,
	}, &got)

	if got.Name != "alice" || got.Count != 9 {
		t.Fatalf("ParseDeserialized result = %#v", got)
	}
}

func TestCompareArgs(t *testing.T) {
	t.Parallel()

	type sample struct {
		Name  string
		Count int
	}

	left := sample{Name: "Alice", Count: 3}
	right := sample{Name: "Alice", Count: 3}
	if !CompareArgs(left, right, "Name", "Count") {
		t.Fatalf("CompareArgs should succeed for matching fields")
	}

	right.Count = 4
	if CompareArgs(left, right, "Name", "Count") {
		t.Fatalf("CompareArgs should fail when any field differs")
	}

	if !ComparePreprocessedArgs(left, sample{Name: "alice", Count: 3}, func(a any) any {
		if s, ok := a.(string); ok {
			return strings.ToLower(s)
		}
		return a
	}, "Name", "Count") {
		t.Fatalf("ComparePreprocessedArgs should use the provided preprocessor")
	}
}

func TestSanitizer(t *testing.T) {
	t.Parallel()

	type sample struct {
		Always string
		Admin  string `sanitizer:"admin"`
		Public string `sanitizer:"public"`
		Hidden string `sanitizer:"-"`
	}

	input := sample{
		Always: "always",
		Admin:  "admin",
		Public: "public",
		Hidden: "hidden",
	}

	got := Sanitizer(input, "public")
	if got.Always != "always" || got.Public != "public" {
		t.Fatalf("Sanitizer should keep untagged and matching tagged fields: %#v", got)
	}
	if got.Admin != "" || got.Hidden != "" {
		t.Fatalf("Sanitizer should omit non-matching or hidden fields: %#v", got)
	}

	all := Sanitizer(input, "-")
	if all.Admin != "admin" || all.Public != "public" || all.Hidden != "" {
		t.Fatalf("Sanitizer wildcard result = %#v", all)
	}
}
