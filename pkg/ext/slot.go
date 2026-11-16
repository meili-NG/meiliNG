package ext

import "sync"

// Slot holds a single replaceable value with a built-in default. Core declares
// a Slot for every piece of behaviour or content a distribution may want to
// swap out (a message template, embedded assets, ...), and a distribution
// replaces it from init():
//
//	func init() {
//		templates.VerificationCode.Override(myVerificationCode)
//	}
//
// The last Override wins. Core reads the active value with Get, so an
// override applies everywhere the slot is used without core changes.
type Slot[T any] struct {
	mu         sync.RWMutex
	def        T
	cur        T
	overridden bool
}

// NewSlot returns a slot whose value is def until overridden.
func NewSlot[T any](def T) *Slot[T] {
	return &Slot[T]{def: def, cur: def}
}

// Get returns the active value: the latest override, or the default.
func (s *Slot[T]) Get() T {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Default returns the built-in value regardless of any override, so an
// override can wrap or fall back to it.
func (s *Slot[T]) Default() T {
	return s.def
}

// Override replaces the active value.
func (s *Slot[T]) Override(v T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur = v
	s.overridden = true
}

// Overridden reports whether the default has been replaced.
func (s *Slot[T]) Overridden() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.overridden
}

// Reset restores the default. It exists for tests.
func (s *Slot[T]) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur = s.def
	s.overridden = false
}
