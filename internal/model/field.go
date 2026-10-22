package model

import (
	"strings"
	"time"
)

// Field is the effective value of one setting: either what a file sets
// explicitly, or the node default when the key is absent. Keeping the two
// cases apart matters because many rules fire on defaults.
type Field struct {
	Path string
	// Set is true when the key is present in a scanned file.
	Set bool
	// Value is the explicit value, the node default when !Set, or nil when the
	// key is absent and has no known default.
	Value any
	// Loc is where the key is set. For absent keys it is the closest enclosing
	// table that exists, so findings still point somewhere useful.
	Loc Location
}

// Get returns the effective value of a top-level dotted path, such as
// "WebServer.TLS.HTTPSPort".
func (d *TOMLDoc) Get(path string) Field {
	return d.GetIn(d.Root, path, path)
}

// GetIn resolves path relative to v (typically an element of an array of
// tables such as one [[EVM.Nodes]] entry). defaultKey names the entry in the
// defaults table, for example "EVM.Nodes.SendOnly".
func (d *TOMLDoc) GetIn(v *Value, path, defaultKey string) Field {
	f := Field{Path: path}
	cur := v
	if cur != nil {
		f.Loc = cur.Loc
	}
	for _, part := range strings.Split(path, ".") {
		if cur == nil || cur.Kind != TableValue {
			cur = nil
			break
		}
		next := cur.Table[part]
		if next == nil {
			cur = nil
			break
		}
		cur = next
		f.Loc = cur.Loc
	}

	if cur != nil {
		f.Set = true
		if cur.Kind == ScalarValue {
			f.Value = cur.Scalar
		} else {
			f.Value = cur
		}
		return f
	}
	if def, ok := defaultFor(d.Kind, defaultKey); ok {
		f.Value = def
	}
	return f
}

// Bool returns the value as a bool. ok is false when the value is missing or
// has another type (the node would reject such a file anyway).
func (f Field) Bool() (value, ok bool) {
	value, ok = f.Value.(bool)
	return value, ok
}

// String returns the value as a string, or "" and false.
func (f Field) String() (string, bool) {
	s, ok := f.Value.(string)
	return s, ok
}

// Int returns the value as an int64, or 0 and false.
func (f Field) Int() (int64, bool) {
	i, ok := f.Value.(int64)
	return i, ok
}

// Duration parses a duration string such as "15m" (the node uses Go's
// time.ParseDuration syntax for durations).
func (f Field) Duration() (time.Duration, bool) {
	s, ok := f.Value.(string)
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false
	}
	return d, true
}

// IsTrue reports whether the effective value is the boolean true.
func (f Field) IsTrue() bool {
	b, ok := f.Bool()
	return ok && b
}
