package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brennocm/oraclint/internal/loader"
	"github.com/brennocm/oraclint/internal/model"
)

// fixtureRoot holds testdata/<RULE-ID>/{vulnerable,safe}/ for every rule.
var fixtureRoot = filepath.Join("..", "..", "testdata")

// TestFixtures checks every rule against its fixture files: each file under
// vulnerable/ must produce at least one finding of that rule, each file under
// safe/ must produce none.
func TestFixtures(t *testing.T) {
	for _, r := range All() {
		m := r.Metadata()
		t.Run(m.ID, func(t *testing.T) {
			for _, dir := range []string{"vulnerable", "safe"} {
				files, err := filepath.Glob(filepath.Join(fixtureRoot, m.ID, dir, "*"))
				if err != nil {
					t.Fatal(err)
				}
				if len(files) == 0 {
					t.Fatalf("no fixtures in testdata/%s/%s", m.ID, dir)
				}
				for _, file := range files {
					n := countFindings(t, r, file)
					if dir == "vulnerable" && n == 0 {
						t.Errorf("%s: expected findings, got none", file)
					}
					if dir == "safe" && n != 0 {
						t.Errorf("%s: expected no findings, got %d", file, n)
					}
				}
			}
		})
	}
}

func countFindings(t *testing.T, r Rule, file string) int {
	t.Helper()
	kind := fixtureKind(r.Metadata(), filepath.Base(file))
	var opts loader.Options
	switch kind {
	case model.KindConfig:
		opts.Config = []string{file}
	case model.KindSecrets:
		opts.Secrets = []string{file}
	case model.KindCompose:
		opts.Compose = []string{file}
	case model.KindK8s:
		opts.K8s = []string{file}
	case model.KindEnv:
		opts.Env = []string{file}
	}
	res, err := loader.Load(nil, opts)
	if err != nil {
		t.Fatalf("load %s: %v", file, err)
	}
	if len(res.Problems) > 0 {
		t.Fatalf("fixture %s does not parse: %v", file, res.Problems[0])
	}
	n := 0
	for _, tg := range res.Targets {
		if !r.Metadata().AppliesTo(tg.Kind) {
			t.Fatalf("fixture %s loaded as %s, which %s does not check", file, tg.Kind, r.Metadata().ID)
		}
		n += len(r.Check(tg))
	}
	return n
}

// fixtureKind picks the file kind for a fixture: the rule's only target, or
// for multi-target rules a "<kind>-" file name prefix (e.g. "k8s-deploy.yaml").
func fixtureKind(m Metadata, name string) model.Kind {
	if len(m.Targets) == 1 {
		return m.Targets[0]
	}
	for _, k := range m.Targets {
		if strings.HasPrefix(name, k.String()+"-") {
			return k
		}
	}
	return m.Targets[0]
}

// TestFixturesHaveNoStrayDirectories catches typos such as testdata/NS-KS-01.
func TestFixturesHaveNoStrayDirectories(t *testing.T) {
	entries, err := os.ReadDir(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "NS-") {
			continue
		}
		if _, ok := ByID(e.Name()); !ok {
			t.Errorf("testdata/%s does not belong to any rule", e.Name())
		}
	}
}
