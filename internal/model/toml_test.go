package model

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const sampleConfig = `# sample node config
InsecureFastScrypt = true
Log.Level = 'debug'

[WebServer]
HTTPPort = 6688
  [WebServer.TLS]
  HTTPSPort = 0

[[EVM]]
ChainID = '1'

[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'http://rpc.example.com'

[[EVM.Nodes]]
Name = 'backup'
WSURL = 'wss://rpc2.example.com'

[[EVM]]
ChainID = '10'
Nodes = [
  { Name = 'inline-a', HTTPURL = 'https://a.example' },
  { Name = 'inline-b', HTTPURL = 'https://b.example' },
]

[Tracing.Attributes]
env = "prod"
`

func TestParseTOMLPositions(t *testing.T) {
	root, err := ParseTOML("config.toml", []byte(sampleConfig))
	if err != nil {
		t.Fatalf("ParseTOML: %v", err)
	}

	tests := []struct {
		name     string
		get      func() *Value
		wantLine int
		wantCol  int
		want     any
	}{
		{"top-level key", func() *Value { return root.Get("InsecureFastScrypt") }, 2, 1, true},
		{"dotted key at root", func() *Value { return root.Get("Log.Level") }, 3, 1, "debug"},
		{"table header", func() *Value { return root.Get("WebServer") }, 5, 2, nil},
		{"key in table", func() *Value { return root.Get("WebServer.HTTPPort") }, 6, 1, int64(6688)},
		{"indented sub-table key", func() *Value { return root.Get("WebServer.TLS.HTTPSPort") }, 8, 3, int64(0)},
		{"first chain", func() *Value { return root.Get("EVM").Items()[0].Get("ChainID") }, 11, 1, "1"},
		{"first node of first chain", func() *Value {
			return root.Get("EVM").Items()[0].Get("Nodes").Items()[0].Get("HTTPURL")
		}, 15, 1, "http://rpc.example.com"},
		{"second node of first chain", func() *Value {
			return root.Get("EVM").Items()[0].Get("Nodes").Items()[1].Get("WSURL")
		}, 19, 1, "wss://rpc2.example.com"},
		{"inline table in array", func() *Value {
			return root.Get("EVM").Items()[1].Get("Nodes").Items()[1].Get("HTTPURL")
		}, 25, 24, "https://b.example"},
		{"quoted-free sub table", func() *Value { return root.Get("Tracing.Attributes.env") }, 29, 1, "prod"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.get()
			if v == nil {
				t.Fatal("value not found")
			}
			if v.Loc.File != "config.toml" || v.Loc.Line != tc.wantLine || v.Loc.Column != tc.wantCol {
				t.Errorf("location = %v, want config.toml:%d:%d", v.Loc, tc.wantLine, tc.wantCol)
			}
			if tc.want != nil && v.Scalar != tc.want {
				t.Errorf("value = %#v, want %#v", v.Scalar, tc.want)
			}
		})
	}
}

func TestParseTOMLInputs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		wantLine  int
		wantKeys  int
		forbidMsg string // text that must not leak into the error message
	}{
		{name: "empty", input: "", wantKeys: 0},
		{name: "only comments", input: "# nothing\n\n", wantKeys: 0},
		{name: "unknown keys are kept", input: "Foo = 1\n[Bar]\nBaz = 'x'\n", wantKeys: 2},
		{name: "utf-8 BOM", input: "\xEF\xBB\xBFLog.Level = 'info'\n", wantKeys: 1},
		{name: "CRLF line endings", input: "[Log]\r\nLevel = 'warn'\r\n", wantKeys: 1},
		{name: "missing equals", input: "[Log]\nLevel 'warn'\n", wantErr: true, wantLine: 2},
		{name: "duplicate key", input: "A = 1\nA = 2\n", wantErr: true, wantLine: 2},
		{
			name:      "unterminated string does not echo content",
			input:     "[Password]\nKeystore = 'hunter2-super-secret\n",
			wantErr:   true,
			wantLine:  2,
			forbidMsg: "hunter2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, err := ParseTOML("f.toml", []byte(tc.input))
			if tc.wantErr {
				var pe *ParseError
				if !errors.As(err, &pe) {
					t.Fatalf("error = %v, want *ParseError", err)
				}
				if pe.Loc.Line != tc.wantLine {
					t.Errorf("error line = %d, want %d (%v)", pe.Loc.Line, tc.wantLine, pe)
				}
				if tc.forbidMsg != "" && containsFold(pe.Error(), tc.forbidMsg) {
					t.Errorf("error message leaks file content: %q", pe.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := len(root.Table); got != tc.wantKeys {
				t.Errorf("top-level keys = %d, want %d", got, tc.wantKeys)
			}
		})
	}
}

func TestLineIndex(t *testing.T) {
	li := newLineIndex([]byte("ab\ncd\n\nef"))
	tests := []struct {
		offset, line, col int
	}{
		{0, 1, 1}, {1, 1, 2}, {3, 2, 1}, {4, 2, 2}, {6, 3, 1}, {7, 4, 1}, {8, 4, 2},
	}
	for _, tc := range tests {
		got := li.location(tc.offset)
		if got.Line != tc.line || got.Column != tc.col {
			t.Errorf("offset %d: got %d:%d, want %d:%d", tc.offset, got.Line, got.Column, tc.line, tc.col)
		}
	}
}

func FuzzParseTOML(f *testing.F) {
	f.Add([]byte(sampleConfig))
	seeds, _ := filepath.Glob(filepath.Join("testdata", "*.toml")) // Glob only fails on a bad pattern
	for _, path := range seeds {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		root, err := ParseTOML("fuzz.toml", data)
		if err != nil {
			return
		}
		doc := &TOMLDoc{Kind: KindConfig, Root: root}
		_ = doc.Get("WebServer.TLS.HTTPSPort") // must not panic
		_ = Merge(root, root)
	})
}
