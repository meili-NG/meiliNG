package config

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
)

// Config sections let optional components, such as a vendor notification
// provider linked in by a build tag or an out-of-tree module, own their
// settings instead of adding fields to MeilingConfig. A component registers
// its config struct from init():
//
//	type Config struct {
//		APIKey string `json:"apiKey"`
//	}
//
//	func init() { config.RegisterSection[Config]("notification.vendor") }
//
// The loader then treats the struct like any built-in section: its keys are
// read from config files, `default` tags apply, and
// MEILING_NOTIFICATION__VENDOR__API_KEY sets it. The component reads the
// loaded value with Section. A build that does not link the component has no
// trace of its keys.

var (
	sectionsMu sync.RWMutex
	sections   = map[string]reflect.Type{}
)

// RegisterSection registers T, a struct, as the config section at path, a
// dotted config key such as "notification.vendor". It panics if the path is
// already registered or T is not a struct, as both are programming errors.
func RegisterSection[T any](path string) {
	t := reflect.TypeOf((*T)(nil)).Elem()
	if t.Kind() != reflect.Struct {
		panic(fmt.Sprintf("config: section %q must be a struct, got %s", path, t))
	}

	sectionsMu.Lock()
	defer sectionsMu.Unlock()
	if _, exists := sections[path]; exists {
		panic(fmt.Sprintf("config: section %q registered twice", path))
	}
	sections[path] = t
}

// RegisteredSections returns the registered section paths, sorted, with the
// struct type of each.
func RegisteredSections() []SectionType {
	sectionsMu.RLock()
	defer sectionsMu.RUnlock()

	out := make([]SectionType, 0, len(sections))
	for path, t := range sections {
		out = append(out, SectionType{Path: path, Type: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// SectionType is a registered section path and its struct type.
type SectionType struct {
	Path string
	Type reflect.Type
}

// Section returns the loaded value of the section registered at path. It
// returns the zero T and false when the section was not loaded, for example
// on a MeilingConfig built in code rather than by the loader.
func Section[T any](cfg *MeilingConfig, path string) (T, bool) {
	var zero T
	if cfg == nil || cfg.Sections == nil {
		return zero, false
	}
	v, ok := cfg.Sections[path].(T)
	if !ok {
		return zero, false
	}
	return v, true
}

// SetSection stores a loaded section value. The loader calls it; tests can use
// it to build a MeilingConfig with a section in code.
func (c *MeilingConfig) SetSection(path string, value any) {
	if c.Sections == nil {
		c.Sections = map[string]any{}
	}
	c.Sections[path] = value
}
