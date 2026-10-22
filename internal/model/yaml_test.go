package model

import (
	"errors"
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
