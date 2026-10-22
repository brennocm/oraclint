package model

import "testing"

func TestMerge(t *testing.T) {
	base := mustParse(t, "base.toml", `
Log.Level = 'info'
[WebServer]
AllowOrigins = 'https://a.example'
HTTPPort = 6688

[[EVM]]
ChainID = '1'
[[EVM.Nodes]]
Name = 'n1'
HTTPURL = 'http://old.example'
[[EVM.Nodes]]
Name = 'n2'
HTTPURL = 'https://n2.example'
`)
	override := mustParse(t, "override.toml", `
[WebServer]
AllowOrigins = '*'

[[EVM]]
ChainID = '1'
[[EVM.Nodes]]
Name = 'n1'
HTTPURL = 'https://new.example'
[[EVM.Nodes]]
Name = 'n3'
HTTPURL = 'https://n3.example'

[[EVM]]
ChainID = '137'
`)

	merged := Merge(base, override)

	tests := []struct {
		name     string
		get      func() *Value
		want     any
		wantFile string
	}{
		{"kept from base", func() *Value { return merged.Get("Log.Level") }, "info", "base.toml"},
		{"overridden scalar", func() *Value { return merged.Get("WebServer.AllowOrigins") }, "*", "override.toml"},
		{"untouched sibling", func() *Value { return merged.Get("WebServer.HTTPPort") }, int64(6688), "base.toml"},
		{"node merged by Name", func() *Value {
			return merged.Get("EVM").Items()[0].Get("Nodes").Items()[0].Get("HTTPURL")
		}, "https://new.example", "override.toml"},
		{"node kept", func() *Value {
			return merged.Get("EVM").Items()[0].Get("Nodes").Items()[1].Get("HTTPURL")
		}, "https://n2.example", "base.toml"},
		{"node appended", func() *Value {
			return merged.Get("EVM").Items()[0].Get("Nodes").Items()[2].Get("HTTPURL")
		}, "https://n3.example", "override.toml"},
		{"chain appended", func() *Value { return merged.Get("EVM").Items()[1].Get("ChainID") }, "137", "override.toml"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.get()
			if v == nil {
				t.Fatal("value missing")
			}
			if v.Scalar != tc.want || v.Loc.File != tc.wantFile {
				t.Errorf("got %#v from %s, want %#v from %s", v.Scalar, v.Loc.File, tc.want, tc.wantFile)
			}
		})
	}
	if n := len(merged.Get("EVM").Items()); n != 2 {
		t.Errorf("chains = %d, want 2", n)
	}
	// Inputs must not be modified.
	if got := base.Get("WebServer.AllowOrigins").Scalar; got != "https://a.example" {
		t.Errorf("base was mutated: %v", got)
	}
}

func TestMergeEdgeCases(t *testing.T) {
	if Merge() != nil {
		t.Error("Merge() should return nil")
	}
	a := mustParse(t, "a.toml", "List = ['x', 'y']\n[T]\nk = 1\n")
	b := mustParse(t, "b.toml", "List = ['z']\nT = 'scalar now'\n")
	m := Merge(a, b)
	if items := m.Get("List").Items(); len(items) != 1 || items[0].Scalar != "z" {
		t.Errorf("plain arrays must be replaced, got %d items", len(items))
	}
	if v := m.Get("T"); v.Kind != ScalarValue {
		t.Errorf("type change should replace the value, got kind %v", v.Kind)
	}
}
