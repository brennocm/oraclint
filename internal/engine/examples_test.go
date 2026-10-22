package engine

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/brennocm/oraclint/internal/loader"
	"github.com/brennocm/oraclint/internal/rules"
)

// copyExample copies examples/<name> into a temp dir and sets the secrets
// file mode, because git does not preserve permission bits.
func copyExample(t *testing.T, name string, secretsMode fs.FileMode) string {
	t.Helper()
	src := filepath.Join("..", "..", "examples", name)
	dst := filepath.Join(t.TempDir(), name)
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o640)
		if d.Name() == "secrets.toml" {
			mode = secretsMode
		}
		if err := os.WriteFile(target, data, mode); err != nil {
			return err
		}
		return os.Chmod(target, mode) // WriteFile is subject to umask
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func scanExample(t *testing.T, dir string) []rules.Finding {
	t.Helper()
	res, err := loader.Load([]string{dir}, loader.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return Run(res.Targets, res.Problems, rules.All(), Options{Experimental: true})
}

// TestInsecureExample pins the exact set of rules the insecure example
// triggers. A rule that silently stops firing (a false negative) fails here.
func TestInsecureExample(t *testing.T) {
	findings := scanExample(t, copyExample(t, "insecure-node", 0o644))

	fired := map[string]bool{}
	for _, f := range findings {
		fired[f.RuleID] = true
	}
	var missing []string
	for _, r := range rules.All() {
		id := r.Metadata().ID
		if runtime.GOOS == "windows" && id == "NS-FS-001" {
			continue
		}
		if !fired[id] && !notInInsecureExample[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("rules not triggered by examples/insecure-node: %s", strings.Join(missing, ", "))
	}
	if fired["parse-error"] {
		t.Error("the insecure example must parse cleanly")
	}
}

// notInInsecureExample lists rules that cannot fire together with others in
// one deployment, with the reason.
var notInInsecureExample = map[string]bool{
	// Needs TLS configured; the example disables HTTPS to trigger NS-WEB-001.
	"NS-WEB-004": true,
}

func TestHardenedExample(t *testing.T) {
	findings := scanExample(t, copyExample(t, "hardened-node", 0o600))
	for _, f := range findings {
		t.Errorf("unexpected finding in hardened example: %s %s: %s", f.Location, f.RuleID, f.Message)
	}
}
