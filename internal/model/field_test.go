package model

import (
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, file, src string) *Value {
	t.Helper()
	root, err := ParseTOML(file, []byte(src))
	if err != nil {
		t.Fatalf("ParseTOML(%s): %v", file, err)
	}
	return root
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func TestFieldDefaults(t *testing.T) {
	doc := &TOMLDoc{Kind: KindConfig, Root: mustParse(t, "c.toml", "[WebServer]\nSecureCookies = false\n")}

	tests := []struct {
		path     string
		wantSet  bool
		want     any
		wantLine int
	}{
		{"WebServer.SecureCookies", true, false, 2},
		{"WebServer.HTTPPort", false, int64(6688), 1},      // default; points at [WebServer]
		{"WebServer.TLS.HTTPSPort", false, int64(6689), 1}, // nearest existing table
		{"InsecureFastScrypt", false, false, 0},            // default; whole file
		{"Unknown.Key", false, nil, 0},                     // no default known
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			f := doc.Get(tc.path)
			if f.Set != tc.wantSet || f.Value != tc.want || f.Loc.Line != tc.wantLine {
				t.Errorf("Get(%q) = {Set:%v Value:%#v Line:%d}, want {Set:%v Value:%#v Line:%d}",
					tc.path, f.Set, f.Value, f.Loc.Line, tc.wantSet, tc.want, tc.wantLine)
			}
		})
	}
}

func TestFieldSecretsDefaults(t *testing.T) {
	doc := &TOMLDoc{Kind: KindSecrets, Root: mustParse(t, "s.toml", "")}
	if b, ok := doc.Get("Database.AllowSimplePasswords").Bool(); !ok || b {
		t.Errorf("AllowSimplePasswords default = %v,%v; want false,true", b, ok)
	}
	// Config defaults must not leak into secrets documents.
	if f := doc.Get("WebServer.HTTPPort"); f.Value != nil {
		t.Errorf("secrets doc returned config default %v", f.Value)
	}
}

func TestFieldGetInArrayElement(t *testing.T) {
	doc := &TOMLDoc{Kind: KindConfig, Root: mustParse(t, "c.toml", "[[EVM]]\nChainID = '1'\n[[EVM.Nodes]]\nName = 'a'\n")}
	node := doc.Root.Get("EVM").Items()[0].Get("Nodes").Items()[0]
	f := doc.GetIn(node, "SendOnly", "EVM.Nodes.SendOnly")
	if f.Set || f.Value != false || f.Loc.Line != 3 {
		t.Errorf("GetIn = %+v, want default false at line 3", f)
	}
}

func TestFieldConversions(t *testing.T) {
	tests := []struct {
		name  string
		field Field
		check func(Field) bool
	}{
		{"bool", Field{Value: true}, func(f Field) bool { b, ok := f.Bool(); return ok && b }},
		{"bool wrong type", Field{Value: "true"}, func(f Field) bool { _, ok := f.Bool(); return !ok }},
		{"string", Field{Value: "x"}, func(f Field) bool { s, ok := f.String(); return ok && s == "x" }},
		{"int", Field{Value: int64(7)}, func(f Field) bool { i, ok := f.Int(); return ok && i == 7 }},
		{"int wrong type", Field{Value: 7.0}, func(f Field) bool { _, ok := f.Int(); return !ok }},
		{"duration", Field{Value: "1h30m"}, func(f Field) bool { d, ok := f.Duration(); return ok && d == 90*time.Minute }},
		{"bad duration", Field{Value: "soon"}, func(f Field) bool { _, ok := f.Duration(); return !ok }},
		{"duration nil", Field{}, func(f Field) bool { _, ok := f.Duration(); return !ok }},
		{"IsTrue nil", Field{}, func(f Field) bool { return !f.IsTrue() }},
	}
	for _, tc := range tests {
		if !tc.check(tc.field) {
			t.Errorf("%s: unexpected conversion result for %#v", tc.name, tc.field.Value)
		}
	}
}
