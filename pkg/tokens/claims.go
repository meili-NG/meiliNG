package tokens

import (
	stdjson "encoding/json"
	"strings"

	"github.com/meili-NG/meiliNG/v2/pkg/ext"
)

// CanonicalClaimsNamespace prefixes Meiling's private JWT claims (token_type,
// grant_type, ...) in Go code: struct tags are written with it. On the wire the
// prefix is the configured namespace instead; the JWT manager swaps it when
// signing and parsing, so code never deals with the configured value.
const CanonicalClaimsNamespace = "urn:meiling:claims:v2:"

// DefaultClaimsNamespace is the namespace used when token.jwt.claimsNamespace is not
// set. A distribution can override it:
//
//	func init() { tokens.DefaultClaimsNamespace.Override("https://example.com/claims/") }
var DefaultClaimsNamespace = ext.NewSlot(CanonicalClaimsNamespace)

// claimsNamespaces maps private claim names between the canonical namespace
// used in code and the namespaces used on the wire.
type claimsNamespaces struct {
	// active is written into new tokens.
	active string
	// readable are accepted when parsing: active first, then any additional
	// configured namespaces.
	readable []string
}

func newClaimsNamespaces(active string, accepting []string) claimsNamespaces {
	if active == "" {
		active = DefaultClaimsNamespace.Get()
	}
	readable := []string{active}
	for _, ns := range accepting {
		if ns != "" && ns != active {
			readable = append(readable, ns)
		}
	}
	return claimsNamespaces{active: active, readable: readable}
}

// encode marshals v to a JSON object with canonical claim names rewritten to
// the active namespace.
func (n claimsNamespaces) encode(v any) (map[string]stdjson.RawMessage, error) {
	raw, err := stdjson.Marshal(v)
	if err != nil {
		return nil, err
	}
	var obj map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	if n.active == CanonicalClaimsNamespace {
		return obj, nil
	}
	return renamePrefix(obj, CanonicalClaimsNamespace, n.active), nil
}

// decode rewrites a verified token payload so readable namespaces carry the
// canonical prefix that struct tags expect. Claims under a namespace that is
// not readable are dropped, so a claim is never honored under a name this
// instance was not configured to trust. When several readable namespaces carry
// the same claim, the earlier one (the active namespace first) wins.
func (n claimsNamespaces) decode(payload []byte) ([]byte, error) {
	var obj map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(payload, &obj); err != nil {
		return nil, err
	}

	out := make(map[string]stdjson.RawMessage, len(obj))
	for key, value := range obj {
		if !n.isNamespaced(key) {
			out[key] = value
		}
	}
	for i := len(n.readable) - 1; i >= 0; i-- {
		ns := n.readable[i]
		for key, value := range obj {
			if strings.HasPrefix(key, ns) {
				out[CanonicalClaimsNamespace+strings.TrimPrefix(key, ns)] = value
			}
		}
	}
	return stdjson.Marshal(out)
}

// isNamespaced reports whether key is a private claim under the canonical or a
// readable namespace.
func (n claimsNamespaces) isNamespaced(key string) bool {
	if strings.HasPrefix(key, CanonicalClaimsNamespace) {
		return true
	}
	for _, ns := range n.readable {
		if strings.HasPrefix(key, ns) {
			return true
		}
	}
	return false
}

func renamePrefix(obj map[string]stdjson.RawMessage, from, to string) map[string]stdjson.RawMessage {
	out := make(map[string]stdjson.RawMessage, len(obj))
	for key, value := range obj {
		if strings.HasPrefix(key, from) {
			key = to + strings.TrimPrefix(key, from)
		}
		out[key] = value
	}
	return out
}

// SessionSchemes are the Authorization schemes accepted as aliases of Bearer
// for session tokens. A distribution replaces the list to add or drop one.
var SessionSchemes = ext.NewSlot([]string{"MeilingV2"})

// IsSessionScheme reports whether method is one of SessionSchemes, ignoring
// case as HTTP auth schemes do.
func IsSessionScheme(method string) bool {
	for _, scheme := range SessionSchemes.Get() {
		if strings.EqualFold(method, scheme) {
			return true
		}
	}
	return false
}
