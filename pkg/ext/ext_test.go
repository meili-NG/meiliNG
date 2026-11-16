package ext

import (
	"context"
	"errors"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

type stubHost struct{ cfg *config.MeilingConfig }

func (h stubHost) Config() *config.MeilingConfig { return h.cfg }

type initExt struct {
	name  string
	err   error
	calls *[]string
}

func (e initExt) Name() string { return e.name }

func (e initExt) Init(_ context.Context, host Host) error {
	if host.Config() == nil {
		return errors.New("nil config")
	}
	*e.calls = append(*e.calls, e.name)
	return e.err
}

type plainExt struct{ name string }

func (e plainExt) Name() string { return e.name }

func resetRegistry(t *testing.T) {
	t.Helper()
	registryMu.Lock()
	saved, savedNames := registry, names
	registry, names = nil, map[string]bool{}
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry, names = saved, savedNames
		registryMu.Unlock()
	})
}

func TestRunInitializersInOrderSkippingNonInitializers(t *testing.T) {
	resetRegistry(t)
	var calls []string
	Register(initExt{name: "a", calls: &calls})
	Register(plainExt{name: "b"})
	Register(initExt{name: "c", calls: &calls})

	if err := RunInitializers(context.Background(), stubHost{cfg: &config.MeilingConfig{}}); err != nil {
		t.Fatalf("RunInitializers: %v", err)
	}
	if len(calls) != 2 || calls[0] != "a" || calls[1] != "c" {
		t.Fatalf("calls = %v, want [a c]", calls)
	}
}

func TestRunInitializersStopsAtFirstError(t *testing.T) {
	resetRegistry(t)
	var calls []string
	errInit := errors.New("init failed")
	Register(initExt{name: "a", err: errInit, calls: &calls})
	Register(initExt{name: "b", calls: &calls})

	err := RunInitializers(context.Background(), stubHost{cfg: &config.MeilingConfig{}})
	if !errors.Is(err, errInit) {
		t.Fatalf("err = %v, want wrapping %v", err, errInit)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %v, want only a", calls)
	}
}

func TestRegisterRejectsDuplicateName(t *testing.T) {
	resetRegistry(t)
	Register(plainExt{name: "dup"})
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate Register did not panic")
		}
	}()
	Register(plainExt{name: "dup"})
}

func TestSlotOverrideAndReset(t *testing.T) {
	s := NewSlot("default")
	if s.Get() != "default" || s.Overridden() {
		t.Fatalf("fresh slot = %q overridden=%v", s.Get(), s.Overridden())
	}

	s.Override("custom")
	if s.Get() != "custom" || !s.Overridden() || s.Default() != "default" {
		t.Fatalf("after override: get=%q default=%q overridden=%v", s.Get(), s.Default(), s.Overridden())
	}

	s.Reset()
	if s.Get() != "default" || s.Overridden() {
		t.Fatalf("after reset: get=%q overridden=%v", s.Get(), s.Overridden())
	}
}

type shutdownExt struct {
	name  string
	err   error
	calls *[]string
}

func (e shutdownExt) Name() string { return e.name }

func (e shutdownExt) Shutdown(context.Context) error {
	*e.calls = append(*e.calls, e.name)
	return e.err
}

func TestRunShutdownersReverseOrderAndJoinsErrors(t *testing.T) {
	resetRegistry(t)
	var calls []string
	errA, errC := errors.New("a failed"), errors.New("c failed")
	Register(shutdownExt{name: "a", err: errA, calls: &calls})
	Register(plainExt{name: "b"})
	Register(shutdownExt{name: "c", err: errC, calls: &calls})

	err := RunShutdowners(context.Background())
	if len(calls) != 2 || calls[0] != "c" || calls[1] != "a" {
		t.Fatalf("calls = %v, want [c a]", calls)
	}
	if !errors.Is(err, errA) || !errors.Is(err, errC) {
		t.Fatalf("err = %v, want both failures joined", err)
	}
}
