package model

import (
	"bytes"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

// ValueKind tells which field of a Value is meaningful.
type ValueKind int

// Kinds of TOML values.
const (
	ScalarValue ValueKind = iota + 1
	TableValue
	ArrayValue
)

// Value is one node of a parsed TOML document, together with the location of
// the key that defined it.
type Value struct {
	Kind   ValueKind
	Scalar any               // string, int64, float64, bool or a toml date/time type
	Table  map[string]*Value // TableValue
	Array  []*Value          // ArrayValue
	Loc    Location
}

// Get returns the child at the given dotted path, or nil if any part is
// missing. Get never descends into arrays; use Array for that.
func (v *Value) Get(path string) *Value {
	cur := v
	for _, part := range strings.Split(path, ".") {
		if cur == nil || cur.Kind != TableValue {
			return nil
		}
		cur = cur.Table[part]
	}
	return cur
}

// Items returns the elements of an array value, or nil for anything else
// (including a nil Value). It makes "for range v.Get(x).Items()" safe.
func (v *Value) Items() []*Value {
	if v == nil || v.Kind != ArrayValue {
		return nil
	}
	return v.Array
}

// SortedKeys returns the keys of a table in lexical order, so that rules
// iterate deterministically (Go map iteration order is random).
func (v *Value) SortedKeys() []string {
	if v == nil || v.Kind != TableValue {
		return nil
	}
	keys := make([]string, 0, len(v.Table))
	for k := range v.Table {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TOMLDoc is a parsed config.toml or secrets.toml (possibly merged from
// several files, see Merge).
type TOMLDoc struct {
	Kind Kind // KindConfig or KindSecrets; selects the defaults table
	Root *Value
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ParseTOML parses a TOML document and records the position of every key.
//
// Values are decoded by go-toml's regular decoder, which implements the full
// TOML spec. Positions come from a second pass with go-toml's low-level
// "unstable" parser, which exposes byte ranges. See ADR 0003.
func ParseTOML(file string, data []byte) (*Value, error) {
	data = bytes.TrimPrefix(data, utf8BOM)

	var decoded map[string]any
	if err := toml.Unmarshal(data, &decoded); err != nil {
		return nil, tomlParseError(file, err)
	}

	positions := indexTOMLPositions(data)
	root := &Value{Kind: TableValue, Table: map[string]*Value{}, Loc: Location{File: file}}
	for key, raw := range decoded {
		root.Table[key] = buildValue(raw, key, root.Loc, positions, file)
	}
	return root, nil
}

// buildValue converts a decoded Go value into a *Value tree, attaching the
// position recorded for path. Values without a recorded position (for example
// elements of a plain array) inherit their parent's location.
func buildValue(raw any, path string, parent Location, positions map[string]Location, file string) *Value {
	loc := parent
	if p, ok := positions[path]; ok {
		loc = p
		loc.File = file
	}

	switch typed := raw.(type) {
	case map[string]any:
		v := &Value{Kind: TableValue, Table: make(map[string]*Value, len(typed)), Loc: loc}
		for key, child := range typed {
			v.Table[key] = buildValue(child, path+"."+key, loc, positions, file)
		}
		return v
	case []any:
		v := &Value{Kind: ArrayValue, Array: make([]*Value, len(typed)), Loc: loc}
		for i, child := range typed {
			v.Array[i] = buildValue(child, path+"["+strconv.Itoa(i)+"]", loc, positions, file)
		}
		return v
	default:
		return &Value{Kind: ScalarValue, Scalar: typed, Loc: loc}
	}
}

// quotedText matches single- or double-quoted text in parser messages.
var quotedText = regexp.MustCompile(`'[^']*'|"[^"]*"`)

// tomlParseError converts a go-toml error into a ParseError. Quoted fragments
// are removed from the message because they may echo file content, which can
// be a secret.
func tomlParseError(file string, err error) *ParseError {
	pe := &ParseError{Loc: Location{File: file}, Msg: "invalid TOML"}
	var derr *toml.DecodeError
	if errors.As(err, &derr) {
		pe.Loc.Line, pe.Loc.Column = derr.Position()
		pe.Msg = "invalid TOML: " + quotedText.ReplaceAllString(strings.TrimPrefix(derr.Error(), "toml: "), "'…'")
	}
	return pe
}

// lineIndex converts byte offsets into line/column pairs in O(log n).
// (unstable.Parser.Shape rescans the input from the start on every call,
// which is quadratic for large files.)
type lineIndex []int // byte offset at which each line starts

func newLineIndex(data []byte) lineIndex {
	idx := lineIndex{0}
	for i, b := range data {
		if b == '\n' {
			idx = append(idx, i+1)
		}
	}
	return idx
}

func (li lineIndex) location(offset int) Location {
	// Index of the last line that starts at or before offset.
	line := sort.SearchInts(li, offset+1) - 1
	return Location{Line: line + 1, Column: offset - li[line] + 1}
}

// tomlIndexer walks the expressions of a TOML document and records where each
// key path is defined. Paths use the same format as buildValue:
// "EVM[0].Nodes[1].HTTPURL".
type tomlIndexer struct {
	lines     lineIndex
	positions map[string]Location
	arrayLen  map[string]int // array-of-tables path -> number of elements seen
	current   string         // path of the table opened by the last header
}

func indexTOMLPositions(data []byte) map[string]Location {
	ix := &tomlIndexer{
		lines:     newLineIndex(data),
		positions: map[string]Location{},
		arrayLen:  map[string]int{},
	}
	var p unstable.Parser
	p.Reset(data)
	for p.NextExpression() {
		ix.expression(p.Expression())
	}
	// A parse error here is not expected (the document was already decoded
	// successfully); if it happens we simply keep the positions found so far.
	return ix.positions
}

func (ix *tomlIndexer) expression(e *unstable.Node) {
	switch e.Kind {
	case unstable.Table:
		parts, loc := ix.key(e.Key())
		ix.recordParents(parts, loc)
		ix.current = ix.resolve(parts)
		ix.record(ix.current, loc)
	case unstable.ArrayTable:
		parts, loc := ix.key(e.Key())
		ix.recordParents(parts, loc)
		base := joinPath(ix.resolve(parts[:len(parts)-1]), parts[len(parts)-1])
		n := ix.arrayLen[base]
		ix.arrayLen[base] = n + 1
		ix.record(base, loc)
		ix.current = base + "[" + strconv.Itoa(n) + "]"
		ix.record(ix.current, loc)
	case unstable.KeyValue:
		parts, loc := ix.key(e.Key())
		path := ix.current
		for _, part := range parts {
			path = joinPath(path, part)
			ix.record(path, loc)
		}
		ix.value(e.Value(), path, loc)
	}
}

// value records positions inside inline tables and arrays.
func (ix *tomlIndexer) value(v *unstable.Node, path string, parent Location) {
	switch v.Kind {
	case unstable.InlineTable:
		for it := v.Children(); it.Next(); {
			kv := it.Node()
			if kv.Kind != unstable.KeyValue {
				continue
			}
			parts, loc := ix.key(kv.Key())
			child := path
			for _, part := range parts {
				child = joinPath(child, part)
				ix.record(child, loc)
			}
			ix.value(kv.Value(), child, loc)
		}
	case unstable.Array:
		i := 0
		for it := v.Children(); it.Next(); {
			elem := it.Node()
			if elem.Kind == unstable.Comment {
				continue
			}
			loc := parent
			if elem.Raw.Length > 0 {
				loc = ix.lines.location(int(elem.Raw.Offset))
			}
			elemPath := path + "[" + strconv.Itoa(i) + "]"
			ix.record(elemPath, loc)
			ix.value(elem, elemPath, loc)
			i++
		}
	}
}

// key returns the parts of a (possibly dotted) key and the location of its
// first part.
func (ix *tomlIndexer) key(it unstable.Iterator) ([]string, Location) {
	var parts []string
	var loc Location
	for it.Next() {
		n := it.Node()
		if len(parts) == 0 {
			loc = ix.lines.location(int(n.Raw.Offset))
		}
		parts = append(parts, string(n.Data))
	}
	return parts, loc
}

// resolve turns header key parts into a concrete path, adding the index of
// the latest element for every array of tables on the way. For example after
// [[EVM]] twice, ["EVM", "Nodes"] resolves to "EVM[1].Nodes".
func (ix *tomlIndexer) resolve(parts []string) string {
	path := ""
	for _, part := range parts {
		path = joinPath(path, part)
		if n := ix.arrayLen[path]; n > 0 {
			path += "[" + strconv.Itoa(n-1) + "]"
		}
	}
	return path
}

// recordParents records the implicit tables created by a header: for
// [Mercury.Credentials.main], "Mercury" and "Mercury.Credentials" are defined
// at that header unless they appeared earlier.
func (ix *tomlIndexer) recordParents(parts []string, loc Location) {
	for i := 1; i < len(parts); i++ {
		ix.record(ix.resolve(parts[:i]), loc)
	}
}

// record keeps the first location seen for a path: the place where the key
// or table was introduced.
func (ix *tomlIndexer) record(path string, loc Location) {
	if _, ok := ix.positions[path]; !ok {
		ix.positions[path] = loc
	}
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}
