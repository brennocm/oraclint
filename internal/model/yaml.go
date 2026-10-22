package model

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"

	"go.yaml.in/yaml/v3"
)

// ParseYAML parses every document of a YAML stream into yaml.Node trees,
// which keep the line and column of each node. Empty documents are skipped.
//
// Aliases are not expanded: rules see alias nodes and must use the helpers
// below, which follow an alias at most once. This avoids "billion laughs"
// style expansion.
func ParseYAML(file string, data []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []*yaml.Node
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, yamlParseError(file, err)
		}
		if root := DocumentRoot(&doc); root != nil && !isEmptyDocument(root) {
			docs = append(docs, root)
		}
	}
}

// isEmptyDocument reports whether a document holds nothing (for example a
// document that only contains comments).
func isEmptyDocument(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null" && n.Value == ""
}

// yamlLine extracts "line N" from yaml.v3 error messages, which have no
// structured position.
var yamlLine = regexp.MustCompile(`line (\d+)`)

func yamlParseError(file string, err error) *ParseError {
	pe := &ParseError{Loc: Location{File: file}, Msg: "invalid YAML"}
	if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
		if n, convErr := strconv.Atoi(m[1]); convErr == nil {
			pe.Loc.Line = n
		}
	}
	return pe
}

// DocumentRoot returns the top-level content node of a document node.
func DocumentRoot(doc *yaml.Node) *yaml.Node {
	if doc == nil {
		return nil
	}
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil
		}
		return Resolve(doc.Content[0])
	}
	return Resolve(doc)
}

// Resolve follows an alias node to its anchor (one level only).
func Resolve(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode {
		return n.Alias
	}
	return n
}

// maxMergeDepth bounds chains of YAML merge keys ("<<: *a" inside an anchor
// that itself merges another one).
const maxMergeDepth = 10

// isMergeKey reports whether a mapping key is the YAML merge key "<<".
func isMergeKey(k *yaml.Node) bool {
	return k.Tag == "!!merge" || (k.Value == "<<" && k.Style == 0)
}

// mergeSources returns the mappings referenced by a merge key value:
// "<<: *a" or "<<: [*a, *b]".
func mergeSources(v *yaml.Node) []*yaml.Node {
	v = Resolve(v)
	if v == nil {
		return nil
	}
	if v.Kind == yaml.MappingNode {
		return []*yaml.Node{v}
	}
	var out []*yaml.Node
	if v.Kind == yaml.SequenceNode {
		for _, item := range v.Content {
			if r := Resolve(item); r != nil && r.Kind == yaml.MappingNode {
				out = append(out, r)
			}
		}
	}
	return out
}

// MapGet returns the value for key in a mapping node, or nil. It also returns
// the key node, whose position is usually the best place to report.
//
// It follows YAML merge keys ("<<: *defaults", common in compose files):
// keys written in the mapping win over merged ones, and earlier merge
// sources win over later ones. If a key is duplicated (invalid YAML that some
// tools accept, keeping the last value) the last occurrence is returned; the
// loader reports the duplicate separately.
func MapGet(m *yaml.Node, key string) (keyNode, value *yaml.Node) {
	return mapGet(Resolve(m), key, 0)
}

func mapGet(m *yaml.Node, key string, depth int) (keyNode, value *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode || depth > maxMergeDepth {
		return nil, nil
	}
	// Content alternates key, value, key, value...
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := m.Content[i]; !isMergeKey(k) && k.Value == key {
			keyNode, value = k, Resolve(m.Content[i+1])
		}
	}
	if keyNode != nil {
		return keyNode, value
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if !isMergeKey(m.Content[i]) {
			continue
		}
		for _, src := range mergeSources(m.Content[i+1]) {
			if k, v := mapGet(src, key, depth+1); k != nil {
				return k, v
			}
		}
	}
	return nil, nil
}

// MapValue is MapGet without the key node.
func MapValue(m *yaml.Node, key string) *yaml.Node {
	_, v := MapGet(m, key)
	return v
}

// MapPairs returns the effective key/value pairs of a mapping node: its own
// keys in document order, then keys contributed by merge keys that the
// mapping does not override. Duplicate keys appear once (last value wins).
func MapPairs(m *yaml.Node) (keys, values []*yaml.Node) {
	seen := map[string]int{}
	collectPairs(Resolve(m), 0, seen, &keys, &values)
	return keys, values
}

func collectPairs(m *yaml.Node, depth int, seen map[string]int, keys, values *[]*yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode || depth > maxMergeDepth {
		return
	}
	var merges []*yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if isMergeKey(k) {
			merges = append(merges, v)
			continue
		}
		if idx, ok := seen[k.Value]; ok {
			if depth == 0 { // a duplicate in the mapping itself: last wins
				(*keys)[idx], (*values)[idx] = k, Resolve(v)
			}
			continue
		}
		seen[k.Value] = len(*keys)
		*keys = append(*keys, k)
		*values = append(*values, Resolve(v))
	}
	for _, v := range merges {
		for _, src := range mergeSources(v) {
			collectPairs(src, depth+1, seen, keys, values)
		}
	}
}

// DuplicateKeys reports mapping keys defined more than once. YAML forbids
// them, docker compose rejects them, but lenient parsers keep the last value,
// so a file could show reviewers one value and deploy another. The walk does
// not follow aliases and is bounded in depth.
func DuplicateKeys(file string, docs []*yaml.Node) []*ParseError {
	var out []*ParseError
	type item struct {
		n     *yaml.Node
		depth int
	}
	stack := make([]item, 0, len(docs))
	for _, d := range docs {
		stack = append(stack, item{d, 0})
	}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n := it.n
		if n == nil || n.Kind == yaml.AliasNode || it.depth > maxYAMLWalkDepth {
			continue
		}
		if n.Kind == yaml.MappingNode {
			first := map[string]int{}
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i]
				if isMergeKey(k) || k.Kind != yaml.ScalarNode {
					continue
				}
				if line, dup := first[k.Value]; dup {
					out = append(out, &ParseError{
						Loc: Location{File: file, Line: k.Line, Column: k.Column},
						Msg: fmt.Sprintf("duplicate key %q (first defined at line %d); tools disagree on which value applies", k.Value, line),
					})
					continue
				}
				first[k.Value] = k.Line
			}
		}
		for _, c := range n.Content {
			stack = append(stack, item{c, it.depth + 1})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Loc.Line < out[j].Loc.Line })
	return out
}

// maxYAMLWalkDepth bounds tree walks over hostile input.
const maxYAMLWalkDepth = 1000

// SeqItems returns the items of a sequence node, or nil.
func SeqItems(n *yaml.Node) []*yaml.Node {
	n = Resolve(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	items := make([]*yaml.Node, len(n.Content))
	for i, c := range n.Content {
		items[i] = Resolve(c)
	}
	return items
}

// ScalarString returns the value of a scalar node.
func ScalarString(n *yaml.Node) (string, bool) {
	n = Resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	return n.Value, true
}

// IsTrue reports whether n is a YAML boolean true.
func IsTrue(n *yaml.Node) bool {
	s, ok := ScalarString(n)
	if !ok {
		return false
	}
	b, err := strconv.ParseBool(s)
	return err == nil && b
}

// YAMLLocation returns the location of a node in file.
func YAMLLocation(file string, n *yaml.Node) Location {
	if n == nil {
		return Location{File: file}
	}
	return Location{File: file, Line: n.Line, Column: n.Column}
}
