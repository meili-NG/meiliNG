package utils

import "sync"

// LazyGet returns an existing pointer or initializes it exactly once under the provided lock.
func LazyGet[T any](mu *sync.RWMutex, current **T, factory func() *T) *T {
	mu.RLock()
	value := *current
	mu.RUnlock()
	if value != nil {
		return value
	}

	mu.Lock()
	defer mu.Unlock()

	if *current == nil {
		*current = factory()
	}

	return *current
}
