package suppress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brennocm/oraclint/internal/model"
	"github.com/brennocm/oraclint/internal/rules"
)

func known(id string) bool { return strings.HasPrefix(id, "NS-") && id != "NS-NOPE-001" }

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".oraclint.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{"valid", "disable:\n  - rule: ns-log-001\n    reason: lab\nignore:\n  - rule: NS-WEB-001\n    paths: [\"a/**\"]\n    reason: lb\n", ""},
		{"empty file", "", ""},
		{"unknown key", "disabled:\n  - rule: NS-LOG-001\n", "field disabled not found"},
		{"missing reason", "disable:\n  - rule: NS-LOG-001\n", "reason is required"},
		{"blank reason", "ignore:\n  - rule: NS-LOG-001\n    paths: [x]\n    reason: '  '\n", "reason is required"},
		{"missing rule", "disable:\n  - reason: x\n", "rule is required"},
		{"unknown rule", "disable:\n  - rule: NS-NOPE-001\n    reason: x\n", "unknown rule"},
		{"ignore without paths", "ignore:\n  - rule: NS-LOG-001\n    reason: x\n", "paths is required"},
		{"bad pattern", "ignore:\n  - rule: NS-LOG-001\n    paths: [\"[\"]\n    reason: x\n", "invalid path pattern"},
		{"not yaml", "disable: [\n", "parsing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeConfig(t, tc.content), known)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tc.name == "valid" && (!cfg.DisabledRules()["NS-LOG-001"] || cfg.Ignore[0].Rule != "NS-WEB-001") {
					t.Errorf("config not normalized: %+v", cfg)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}

	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"), known); err == nil {
		t.Error("missing file should be an error")
	}
	big := writeConfig(t, "# "+strings.Repeat("x", maxConfigSize+1))
	if _, err := LoadConfig(big, known); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized config: %v", err)
	}
	var nilCfg *Config
	if len(nilCfg.DisabledRules()) != 0 {
		t.Error("nil config disables nothing")
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern, file string
		want          bool
	}{
		{"deploy/staging/**", "deploy/staging/config.toml", true},
		{"deploy/staging/**", "deploy/staging/k8s/node.yaml", true},
		{"deploy/staging/**", "deploy/staging-old/config.toml", false},
		{"deploy/*/config.toml", "deploy/prod/config.toml", true},
		{"deploy/*/config.toml", "deploy/prod/x/config.toml", false},
		{"./config.toml", "config.toml", true},
		{"config.toml", "other/config.toml", false},
	}
	for _, tc := range tests {
		if got := matchPath(tc.pattern, tc.file); got != tc.want {
			t.Errorf("matchPath(%q, %q) = %v", tc.pattern, tc.file, got)
		}
	}
}

func finding(id, file string, line int) rules.Finding {
	return rules.Finding{RuleID: id, Severity: rules.SeverityHigh, Location: model.Location{File: file, Line: line}}
}

func TestApply(t *testing.T) {
	src := "a = 1 # oraclint:ignore NS-A-001 reason=\"same line\"\n" + // 1
		"# oraclint:ignore NS-B-001,NS-C-001 reason=\"next line\"\n" + // 2
		"b = 2\n" + // 3
		"c = 3\n" + // 4
		"# oraclint:ignore NS-D-001\n" + // 5: no reason
		"d = 4\n" + // 6
		"e = 5 # oraclint:ignore NS-NOPE-001 reason=\"typo\"\n" // 7
	targets := []*model.Target{{Path: "f.toml", Directives: model.ParseDirectives("f.toml", []byte(src))}}
	cfg := &Config{File: ".oraclint.yaml", Ignore: []IgnoreEntry{{Rule: "NS-E-001", Paths: []string{"f.toml"}, Reason: "cfg"}}}

	in := []rules.Finding{
		finding("NS-A-001", "f.toml", 1), // inline, same line
		finding("NS-B-001", "f.toml", 3), // inline, line below
		finding("NS-C-001", "f.toml", 4), // two lines below: not covered
		finding("NS-D-001", "f.toml", 6), // directive without reason
		finding("NS-E-001", "f.toml", 0), // file-level, via config
		finding("NS-A-001", "g.toml", 1), // other file
		finding("NS-E-001", "g.toml", 2), // config path does not match
	}
	out := Apply(in, targets, cfg, known)

	wantSuppressed := map[int]string{0: rules.SuppressionInline, 1: rules.SuppressionInline, 4: rules.SuppressionConfig}
	invalid := 0
	for i, f := range out {
		if f.RuleID == rules.InvalidSuppression.ID {
			invalid++
			if f.Severity != rules.SeverityInfo {
				t.Errorf("invalid-suppression should be info: %+v", f)
			}
			continue
		}
		kind, want := wantSuppressed[i-2] // the two invalid findings come first
		switch {
		case want && (f.Suppression == nil || f.Suppression.Kind != kind):
			t.Errorf("finding %d (%s line %d) should be suppressed (%s): %+v", i, f.RuleID, f.Location.Line, kind, f.Suppression)
		case !want && f.Suppression != nil:
			t.Errorf("finding %d (%s line %d) should not be suppressed: %+v", i, f.RuleID, f.Location.Line, f.Suppression)
		}
	}
	if invalid != 2 {
		t.Errorf("invalid-suppression findings = %d, want 2 (missing reason, unknown rule)", invalid)
	}
	if out[2].Suppression.Reason != "same line" || out[2].Suppression.Source.Line != 1 {
		t.Errorf("suppression details = %+v", out[2].Suppression)
	}
}
