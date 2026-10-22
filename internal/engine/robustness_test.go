package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brennocm/oraclint/internal/loader"
	"github.com/brennocm/oraclint/internal/rules"
)

// scanWithin runs the full pipeline on files and fails if it takes longer
// than limit. Hostile inputs must be rejected or handled quickly, never hang.
func scanWithin(t *testing.T, limit time.Duration, files map[string][]byte) ([]rules.Finding, *loader.Result) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		findings []rules.Finding
		res      *loader.Result
		err      error
	}
	done := make(chan result, 1)
	go func() {
		res, err := loader.Load([]string{dir}, loader.Options{})
		if err != nil {
			done <- result{err: err}
			return
		}
		done <- result{findings: Run(res.Targets, res.Problems, rules.All(), Options{Experimental: true}), res: res}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.findings, r.res
	case <-time.After(limit):
		t.Fatalf("scan did not finish within %s", limit)
		return nil, nil
	}
}

func hasRule(findings []rules.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestHostileInputs(t *testing.T) {
	// "Billion laughs": nine levels of ten aliases each expand to 10^9 nodes.
	var bomb strings.Builder
	bomb.WriteString("x-a0: &a0 [lol, lol, lol, lol, lol, lol, lol, lol, lol, lol]\n")
	for i := 1; i <= 9; i++ {
		ref := fmt.Sprintf("*a%d", i-1)
		fmt.Fprintf(&bomb, "x-a%d: &a%d [%s]\n", i, i, strings.Repeat(ref+", ", 9)+ref)
	}
	bomb.WriteString("services:\n  chainlink:\n    image: smartcontract/chainlink:latest\n    environment: *a9\n")

	deepTOML := "a = " + strings.Repeat("[", 100000) + strings.Repeat("]", 100000) + "\n"
	deepYAML := "services: " + strings.Repeat("[", 100000) + strings.Repeat("]", 100000) + "\n"

	utf16 := []byte{0xFF, 0xFE} // UTF-16LE BOM, then ASCII bytes each followed by 0
	for _, c := range []byte("[Log]\nLevel = 'debug'\n") {
		utf16 = append(utf16, c, 0)
	}

	binary := make([]byte, 64<<10)
	for i := range binary {
		binary[i] = byte(i*31 + 7)
	}

	tests := []struct {
		name  string
		files map[string][]byte
		check func(t *testing.T, findings []rules.Finding, res *loader.Result)
	}{
		{
			name:  "alias bomb in compose",
			files: map[string][]byte{"docker-compose.yml": []byte(bomb.String())},
			check: func(t *testing.T, f []rules.Finding, _ *loader.Result) {
				if !hasRule(f, "NS-IMG-001") {
					t.Error("rules should still run on the rest of the file")
				}
			},
		},
		{
			name:  "deeply nested TOML",
			files: map[string][]byte{"config.toml": []byte(deepTOML)},
			check: func(t *testing.T, f []rules.Finding, _ *loader.Result) {
				if !hasRule(f, "parse-error") {
					t.Error("expected a parse-error finding")
				}
			},
		},
		{
			name:  "deeply nested YAML",
			files: map[string][]byte{"docker-compose.yml": []byte(deepYAML)},
		},
		{
			name:  "binary data with a node file name",
			files: map[string][]byte{"config.toml": binary, "docker-compose.yml": binary, ".env": binary},
		},
		{
			name:  "UTF-16 is reported, not misread",
			files: map[string][]byte{"config.toml": utf16},
			check: func(t *testing.T, f []rules.Finding, _ *loader.Result) {
				if !hasRule(f, "parse-error") {
					t.Error("UTF-16 config should be reported as unparsable")
				}
			},
		},
		{
			name:  "UTF-8 BOM is accepted",
			files: map[string][]byte{"config.toml": []byte("\xEF\xBB\xBF[Log]\nLevel = 'debug'\n")},
			check: func(t *testing.T, f []rules.Finding, _ *loader.Result) {
				if !hasRule(f, "NS-LOG-001") {
					t.Error("BOM-prefixed config should be scanned normally")
				}
			},
		},
		{
			name:  "file over the size limit",
			files: map[string][]byte{"config.toml": []byte("# " + strings.Repeat("x", loader.DefaultMaxFileSize) + "\n")},
			check: func(t *testing.T, f []rules.Finding, _ *loader.Result) {
				if !hasRule(f, "parse-error") {
					t.Error("oversized node file should be reported")
				}
			},
		},
		{
			name:  "very long single line",
			files: map[string][]byte{".env": []byte("A=" + strings.Repeat("b", 2<<20) + "\n")},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings, res := scanWithin(t, 10*time.Second, tc.files)
			if tc.check != nil {
				tc.check(t, findings, res)
			}
		})
	}
}

func TestTerminalEscapesAreNeutralized(t *testing.T) {
	findings, _ := scanWithin(t, 10*time.Second, map[string][]byte{
		"config.toml": []byte("[Tracing]\nEnabled = true\nMode = 'unencrypted'\nCollectorTarget = \"\\u001b[2J\\u202eevil.example.com:4317\"\n"),
	})
	if !hasRule(findings, "NS-TRC-001") {
		t.Fatal("expected NS-TRC-001")
	}
	for _, f := range findings {
		if strings.ContainsAny(f.Message, "\x1b\u202e") {
			t.Errorf("raw control characters in message: %q", f.Message)
		}
	}
}
