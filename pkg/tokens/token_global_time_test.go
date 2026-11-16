package tokens

import (
	stdjson "encoding/json"
	"testing"
	"time"
)

// decodeRaw round-trips value the way a Valkey record is read back: marshal
// to JSON, then decode into map[string]any.
func decodeRaw(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var data map[string]any
	if err := stdjson.Unmarshal(raw, &data); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return data
}

func TestRawJSONTimeReadsStoredRecords(t *testing.T) {
	revokedAt := time.Now().Add(-time.Minute).Truncate(time.Millisecond)

	t.Run("a payload struct that was never revoked", func(t *testing.T) {
		data := decodeRaw(t, AccessTokenContent{GlobalTokenPayload: GlobalTokenPayload{TID: "t"}})
		if got := rawJSONTime(data["revokedAt"]); got != nil {
			t.Fatalf("revokedAt = %v, want nil", got)
		}
	})

	t.Run("a payload struct with a revocation time", func(t *testing.T) {
		data := decodeRaw(t, AccessTokenContent{GlobalTokenPayload: GlobalTokenPayload{TID: "t", RevokedAt: revokedAt}})
		got := rawJSONTime(data["revokedAt"])
		if got == nil || !got.Equal(revokedAt) {
			t.Fatalf("revokedAt = %v, want %v", got, revokedAt)
		}
	})

	t.Run("a revocation written by Revoke still decodes into the payload", func(t *testing.T) {
		data := decodeRaw(t, AccessTokenContent{GlobalTokenPayload: GlobalTokenPayload{TID: "t"}})
		data["revokedAt"] = revokedAt
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var payload AccessTokenContent
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatalf("payload no longer decodes after revocation: %v", err)
		}
		if !payload.IsRevoked() {
			t.Fatal("decoded payload is not revoked")
		}
		if got := rawJSONTime(decodeRaw(t, payload)["revokedAt"]); got == nil {
			t.Fatal("raw revokedAt was lost")
		}
	})
}
