package rules

import (
	"testing"

	"github.com/brennocm/oraclint/internal/model"
)

// tomlTarget parses src as a config or secrets file named after the kind.
func tomlTarget(t *testing.T, kind model.Kind, src string) *model.Target {
	t.Helper()
	file := kind.String() + ".toml"
	root, err := model.ParseTOML(file, []byte(src))
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return &model.Target{Kind: kind, Path: file, Files: []string{file}, TOML: &model.TOMLDoc{Kind: kind, Root: root}}
}

func configTarget(t *testing.T, src string) *model.Target {
	t.Helper()
	return tomlTarget(t, model.KindConfig, src)
}

func secretsTarget(t *testing.T, src string) *model.Target {
	t.Helper()
	return tomlTarget(t, model.KindSecrets, src)
}

// ruleCase is a common shape for table-driven rule tests: an input and the
// lines where findings are expected (empty means no findings).
type ruleCase struct {
	name      string
	target    func(t *testing.T) *model.Target
	wantLines []int
}

func runRuleCases(t *testing.T, r Rule, cases []ruleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := r.Check(tc.target(t))
			if len(findings) != len(tc.wantLines) {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), len(tc.wantLines), findings)
			}
			for i, f := range findings {
				if f.Location.Line != tc.wantLines[i] {
					t.Errorf("finding %d at line %d, want %d (%s)", i, f.Location.Line, tc.wantLines[i], f.Message)
				}
				if f.RuleID != r.Metadata().ID || f.Severity != r.Metadata().Severity || f.Remediation == "" {
					t.Errorf("finding %d has inconsistent metadata: %+v", i, f)
				}
			}
		})
	}
}

func cfg(src string) func(t *testing.T) *model.Target {
	return func(t *testing.T) *model.Target { t.Helper(); return configTarget(t, src) }
}

func sec(src string) func(t *testing.T) *model.Target {
	return func(t *testing.T) *model.Target { t.Helper(); return secretsTarget(t, src) }
}
