package tokens

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Concurrent claims of one id have exactly one winner, which is what keeps an
// authorization code from being redeemed twice.
func TestClaimHasOneWinner(t *testing.T) {
	m := NewGlobalTokenManager(nil)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := m.Claim("code:abc", time.Minute); err != nil {
				t.Error(err)
			} else if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d claims won, want 1", wins.Load())
	}
	if ok, _ := m.Claim("code:other", time.Minute); !ok {
		t.Fatal("a different id could not be claimed")
	}
}
