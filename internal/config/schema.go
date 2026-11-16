package config

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	pkgconfig "github.com/meili-NG/meiliNG/v2/pkg/config"
)

// keyTag is the struct tag naming a field's config key. It is shared by every
// file format and by SaveConfig, so a key is spelled the same everywhere.
const keyTag = "json"

// envDelimiter separates path segments in structured environment variables:
// MEILING_OAUTH2__ALLOW_CREATE sets oauth2.allowCreate. The prefix is
// pkgconfig.EnvPrefix.
const envDelimiter = "__"

// configField describes one leaf value of MeilingConfig.
type configField struct {
	path   []string
	typ    reflect.Type
	def    string
	hasDef bool
}

// configSchema indexes MeilingConfig so keys from files and environment
// variables can be matched loosely (case, '_' and '-' ignored) and rewritten to
// their canonical spelling before they reach koanf.
type configSchema struct {
	leaves []configField
	// nodes maps a canonical parent path ("" for the root) to its children,
	// keyed by normalized name, valued by canonical name.
	nodes map[string]map[string]string
	// leafByPath maps a canonical dotted path to its leaf.
	leafByPath map[string]*configField
}

// newSchema indexes MeilingConfig and every registered section. It is built
// per load rather than once, because sections register from init() functions
// that may run after this package is initialized.
func newSchema() (*configSchema, error) {
	return buildSchema(reflect.TypeOf(pkgconfig.MeilingConfig{}), pkgconfig.RegisteredSections())
}

func buildSchema(t reflect.Type, sections []pkgconfig.SectionType) (*configSchema, error) {
	s := &configSchema{
		nodes:      map[string]map[string]string{},
		leafByPath: map[string]*configField{},
	}
	s.walk(t, nil)
	for _, section := range sections {
		if err := s.addSection(section); err != nil {
			return nil, err
		}
	}
	for i := range s.leaves {
		leaf := &s.leaves[i]
		s.leafByPath[strings.Join(leaf.path, ".")] = leaf
	}
	return s, nil
}

// addSection grafts a registered section onto the schema at its path. The
// path's last segment must not already name a key, so a section can never
// shadow a built-in setting or another section.
func (s *configSchema) addSection(section pkgconfig.SectionType) error {
	path := strings.Split(section.Path, ".")
	parent := ""
	for i, segment := range path {
		if segment == "" {
			return fmt.Errorf("config section %q: empty path segment", section.Path)
		}
		children := s.nodes[parent]
		if children == nil {
			children = map[string]string{}
			s.nodes[parent] = children
		}

		existing, exists := children[normalizeKey(segment)]
		last := i == len(path)-1
		switch {
		case exists && last:
			return fmt.Errorf("config section %q collides with an existing key", section.Path)
		case exists:
			segment = existing
		default:
			children[normalizeKey(segment)] = segment
		}

		if parent == "" {
			parent = segment
		} else {
			parent += "." + segment
		}
		if _, isLeaf := s.leafByPathBeforeIndex(parent); isLeaf {
			return fmt.Errorf("config section %q is nested under the setting %q", section.Path, parent)
		}
	}

	s.walk(section.Type, strings.Split(parent, "."))
	return nil
}

// leafByPathBeforeIndex looks a leaf up by path while the schema is still being
// built, before leafByPath is filled in.
func (s *configSchema) leafByPathBeforeIndex(path string) (*configField, bool) {
	for i := range s.leaves {
		if strings.Join(s.leaves[i].path, ".") == path {
			return &s.leaves[i], true
		}
	}
	return nil, false
}

func (s *configSchema) walk(t reflect.Type, parent []string) {
	parentKey := strings.Join(parent, ".")
	if s.nodes[parentKey] == nil {
		s.nodes[parentKey] = map[string]string{}
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}

		name := fieldKey(f)
		if name == "" {
			continue
		}
		s.nodes[parentKey][normalizeKey(name)] = name
		path := append(append([]string{}, parent...), name)

		if isNestedConfig(f.Type) {
			s.walk(f.Type, path)
			continue
		}

		def, hasDef := f.Tag.Lookup("default")
		s.leaves = append(s.leaves, configField{
			path:   path,
			typ:    f.Type,
			def:    def,
			hasDef: hasDef,
		})
	}
}

func fieldKey(f reflect.StructField) string {
	tag := f.Tag.Get(keyTag)
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	if name == "" {
		return f.Name
	}
	return name
}

func isNestedConfig(t reflect.Type) bool {
	return t.Kind() == reflect.Struct && t != reflect.TypeOf(time.Time{})
}

func normalizeKey(key string) string {
	key = strings.ToLower(key)
	key = strings.ReplaceAll(key, "_", "")
	return strings.ReplaceAll(key, "-", "")
}

// canonicalize rewrites the keys of a parsed config file to their canonical
// spelling, so `PublicURL`, `public_url` and `publicUrl` all
// land on server.publicUrl. Keys the schema does not know are kept as-is,
// and values below a leaf (such as notification.keys) are never rewritten.
func (s *configSchema) canonicalize(m map[string]any, parent string) map[string]any {
	children := s.nodes[parent]
	if children == nil {
		return m
	}

	out := make(map[string]any, len(m))
	for k, v := range m {
		canonical, ok := children[normalizeKey(k)]
		if !ok {
			out[k] = v
			continue
		}

		path := canonical
		if parent != "" {
			path = parent + "." + canonical
		}
		if sub, ok := v.(map[string]any); ok {
			v = s.canonicalize(sub, path)
		}
		out[canonical] = v
	}
	return out
}

// resolveEnvKey maps the part of a structured environment variable after the
// prefix (OAUTH2__ALLOW_CREATE) to a leaf.
func (s *configSchema) resolveEnvKey(key string) *configField {
	return s.resolveSegments(strings.Split(key, envDelimiter))
}

// resolvePath maps a dotted config key, matched as loosely as file keys, to a
// leaf.
func (s *configSchema) resolvePath(path string) *configField {
	return s.resolveSegments(strings.Split(path, "."))
}

func (s *configSchema) resolveSegments(segments []string) *configField {
	parent := ""
	for _, segment := range segments {
		canonical, ok := s.nodes[parent][normalizeKey(segment)]
		if !ok {
			return nil
		}
		if parent == "" {
			parent = canonical
		} else {
			parent += "." + canonical
		}
	}
	return s.leafByPath[parent]
}

// distributionDefaults returns the values registered with
// pkgconfig.SetDefault as a nested map, failing on a path that names no
// setting.
func (s *configSchema) distributionDefaults() (map[string]any, error) {
	out := map[string]any{}
	for _, d := range pkgconfig.DistributionDefaults() {
		leaf := s.resolvePath(d.Path)
		if leaf == nil {
			return nil, fmt.Errorf("config default %q: no such setting", d.Path)
		}
		value := d.Value
		if str, ok := value.(string); ok {
			value = parseEnvValue(leaf.typ, str)
		}
		setPath(out, leaf.path, value)
	}
	return out, nil
}

// defaults returns the `default` tag values as a nested map.
func (s *configSchema) defaults() map[string]any {
	out := map[string]any{}
	for _, leaf := range s.leaves {
		if leaf.hasDef {
			setPath(out, leaf.path, parseEnvValue(leaf.typ, leaf.def))
		}
	}
	return out
}

// structuredEnvTransform is the koanf env provider transform for MEILING_*
// variables: MEILING_OAUTH2__ALLOW_CREATE becomes oauth2.allowCreate. Variables
// that name no known key, or are empty, are dropped.
func (s *configSchema) structuredEnvTransform(key, value string) (string, any) {
	leaf := s.resolveEnvKey(strings.TrimPrefix(key, pkgconfig.EnvPrefix()))
	if leaf == nil || value == "" {
		return "", nil
	}
	return strings.Join(leaf.path, "."), parseEnvValue(leaf.typ, value)
}

// parseEnvValue converts a string from an environment variable or a default
// tag into the shape its field expects. Lists are comma-separated and maps are
// comma-separated key:value pairs; scalars stay strings and are converted by
// the decoder.
func parseEnvValue(t reflect.Type, value string) any {
	switch t.Kind() {
	case reflect.Slice:
		items := []any{}
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				items = append(items, item)
			}
		}
		return items
	case reflect.Map:
		pairs := map[string]any{}
		for _, item := range strings.Split(value, ",") {
			k, v, ok := strings.Cut(item, ":")
			if !ok {
				continue
			}
			pairs[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		return pairs
	default:
		return value
	}
}

func setPath(m map[string]any, path []string, value any) {
	for _, key := range path[:len(path)-1] {
		next, ok := m[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[key] = next
		}
		m = next
	}
	m[path[len(path)-1]] = value
}
