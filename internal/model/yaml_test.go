package model

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseYAMLMultiDoc(t *testing.T) {
	src := `apiVersion: v1
kind: Service
metadata:
  name: node
---
# empty document follows
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true
`
	docs, err := ParseYAML("k8s.yaml", []byte(src))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("documents = %d, want 2", len(docs))
	}
	kind, _ := ScalarString(MapValue(docs[1], "kind"))
	if kind != "Deployment" {
		t.Errorf("kind = %q", kind)
	}
	spec := MapValue(MapValue(MapValue(docs[1], "spec"), "template"), "spec")
	key, val := MapGet(spec, "hostNetwork")
	if !IsTrue(val) {
		t.Error("hostNetwork should be true")
	}
	if loc := YAMLLocation("k8s.yaml", key); loc.Line != 13 || loc.Column != 7 {
		t.Errorf("hostNetwork location = %v, want line 13 col 7", loc)
	}
}

func TestParseYAMLErrorsAndHelpers(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		wantErr  bool
		wantLine int
		wantDocs int
	}{
		{name: "empty", src: "", wantDocs: 0},
		{name: "scalar doc", src: "hello\n", wantDocs: 1},
		{name: "bad indentation", src: "a:\n  b: 1\n c: 2\n", wantErr: true},
		{name: "mapping in scalar", src: "a: 1\nb: c: d\n", wantErr: true, wantLine: 2},
		{name: "unclosed quote", src: "a: \"secret-value\nb: 1\n", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docs, err := ParseYAML("f.yaml", []byte(tc.src))
			if tc.wantErr {
				var pe *ParseError
				if !errors.As(err, &pe) {
					t.Fatalf("error = %v, want *ParseError", err)
				}
				if tc.wantLine != 0 && pe.Loc.Line != tc.wantLine {
					t.Errorf("line = %d, want %d", pe.Loc.Line, tc.wantLine)
				}
				if containsFold(pe.Msg, "secret-value") {
					t.Errorf("error leaks content: %q", pe.Msg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(docs) != tc.wantDocs {
				t.Errorf("docs = %d, want %d", len(docs), tc.wantDocs)
			}
		})
	}

	// Helpers must tolerate nil and wrong node kinds.
	if MapValue(nil, "x") != nil || SeqItems(nil) != nil || IsTrue(nil) {
		t.Error("helpers should handle nil")
	}
	if k, v := MapPairs(nil); k != nil || v != nil {
		t.Error("MapPairs(nil) should return nils")
	}
	if loc := YAMLLocation("f", nil); loc.Line != 0 {
		t.Error("YAMLLocation(nil) should have no line")
	}
}

func TestYAMLAliasesAreNotExpanded(t *testing.T) {
	src := `base: &b
  privileged: true
svc:
  security: *b
list: [*b, *b]
`
	docs, err := ParseYAML("a.yaml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	sec := MapValue(MapValue(docs[0], "svc"), "security")
	if !IsTrue(MapValue(sec, "privileged")) {
		t.Error("alias should resolve to its anchor")
	}
	if n := len(SeqItems(MapValue(docs[0], "list"))); n != 2 {
		t.Errorf("list items = %d", n)
	}
	keys, _ := MapPairs(docs[0])
	if len(keys) != 3 {
		t.Errorf("keys = %d", len(keys))
	}
}

func FuzzParseYAML(f *testing.F) {
	f.Add([]byte("services:\n  node:\n    image: smartcontract/chainlink:2.69.0\n    ports: ['6688:6688']\n"))
	f.Add([]byte("a: &a [*a]\n"))
	f.Add([]byte("apiVersion: v1\nkind: Pod\n---\nx: y\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		docs, err := ParseYAML("fuzz.yaml", data)
		if err != nil {
			return
		}
		for _, d := range docs {
			keys, values := MapPairs(d)
			for i := range keys {
				_ = SeqItems(values[i])
				_, _ = ScalarString(values[i])
			}
		}
	})
}

func TestYAMLMergeKeys(t *testing.T) {
	src := `x-base: &base
  privileged: true
  user: root
x-more: &more
  pid: host
  user: nobody
svc:
  <<: [*base, *more]
  user: "14933"
  image: a:1
env:
  <<: *base
  extra: 1
`
	docs, err := ParseYAML("c.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	svc := MapValue(docs[0], "svc")
	tests := []struct{ key, want string }{
		{"privileged", "true"}, // from the first merge source
		{"pid", "host"},        // from the second
		{"user", "14933"},      // explicit key wins over merged ones
		{"image", "a:1"},
	}
	for _, tc := range tests {
		k, v := MapGet(svc, tc.key)
		if got, _ := ScalarString(v); got != tc.want || k == nil {
			t.Errorf("MapGet(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
	keys, _ := MapPairs(MapValue(docs[0], "env"))
	var names []string
	for _, k := range keys {
		names = append(names, k.Value)
	}
	if strings.Join(names, ",") != "extra,privileged,user" {
		t.Errorf("MapPairs with merge = %v", names)
	}
}

func TestYAMLMergeCycleIsBounded(t *testing.T) {
	// yaml.v3 refuses an anchor that contains itself; a long chain of merges
	// is still bounded by maxMergeDepth.
	var b strings.Builder
	b.WriteString("a0: &a0 {k: v}\n")
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&b, "a%d: &a%d {<<: *a%d}\n", i, i, i-1)
	}
	docs, err := ParseYAML("c.yml", []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if v := MapValue(MapValue(docs[0], "a30"), "k"); v != nil {
		t.Error("lookups deeper than maxMergeDepth must stop")
	}
	if v := MapValue(MapValue(docs[0], "a5"), "k"); v == nil {
		t.Error("shallow merge chains must resolve")
	}
}

func TestDuplicateKeys(t *testing.T) {
	src := "a: 1\nb:\n  c: 1\n  c: 2\na: 3\nx: &x {k: 1}\ny: *x\nz:\n  <<: *x\n  <<: *x\n"
	docs, err := ParseYAML("d.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	dups := DuplicateKeys("d.yml", docs)
	if len(dups) != 2 || dups[0].Loc.Line != 4 || dups[1].Loc.Line != 5 {
		t.Fatalf("duplicates = %+v", dups)
	}
	if !strings.Contains(dups[1].Msg, `duplicate key "a" (first defined at line 1)`) {
		t.Errorf("message = %q", dups[1].Msg)
	}
	// Last value wins for lookups, matching lenient parsers.
	if v, _ := ScalarString(MapValue(docs[0], "a")); v != "3" {
		t.Errorf("MapGet on duplicate = %q, want last value", v)
	}
}
