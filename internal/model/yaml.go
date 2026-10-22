package model

import (
	"bytes"
	"errors"
	"io"
	"regexp"
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

// MapGet returns the value for key in a mapping node, or nil. It also returns
// the key node, whose position is usually the best place to report.
func MapGet(m *yaml.Node, key string) (keyNode, value *yaml.Node) {
	m = Resolve(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	// Content alternates key, value, key, value...
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], Resolve(m.Content[i+1])
		}
	}
	return nil, nil
}

// MapValue is MapGet without the key node.
func MapValue(m *yaml.Node, key string) *yaml.Node {
	_, v := MapGet(m, key)
	return v
}

// MapPairs returns the key/value pairs of a mapping node in document order.
func MapPairs(m *yaml.Node) (keys, values []*yaml.Node) {
	m = Resolve(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		keys = append(keys, m.Content[i])
		values = append(values, Resolve(m.Content[i+1]))
	}
	return keys, values
}

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
