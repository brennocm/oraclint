package engine

import (
	"fmt"
	"strings"
	"testing"

	"github.com/brennocm/oraclint/internal/model"
	"github.com/brennocm/oraclint/internal/rules"
)

// fakeRule reports one finding per target at a fixed location.
type fakeRule struct {
	id     string
	sev    rules.Severity
	status rules.Status
	kind   model.Kind
	line   int
}

func (r fakeRule) Metadata() rules.Metadata {
	return rules.Metadata{ID: r.id, Severity: r.sev, Status: r.status, Targets: []model.Kind{r.kind}}
}

func (r fakeRule) Check(t *model.Target) []rules.Finding {
	return []rules.Finding{{
		RuleID: r.id, Severity: r.sev, Message: "found by " + r.id,
		Location: model.Location{File: t.Path, Line: r.line},
	}}
}

func ids(findings []rules.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = fmt.Sprintf("%s@%s:%d", f.RuleID, f.Location.File, f.Location.Line)
	}
	return out
}

func TestRun(t *testing.T) {
	all := []rules.Rule{
		fakeRule{"NS-B-001", rules.SeverityHigh, rules.Stable, model.KindConfig, 5},
		fakeRule{"NS-A-001", rules.SeverityLow, rules.Stable, model.KindConfig, 5},
		fakeRule{"NS-C-001", rules.SeverityMedium, rules.Experimental, model.KindConfig, 1},
		fakeRule{"NS-D-001", rules.SeverityCritical, rules.Stable, model.KindSecrets, 2},
	}
	targets := []*model.Target{
		{Kind: model.KindSecrets, Path: "b/secrets.toml"},
		{Kind: model.KindConfig, Path: "a/config.toml"},
	}
	problems := []*model.ParseError{{Loc: model.Location{File: "c/compose.yml", Line: 3}, Msg: "invalid YAML"}}

	tests := []struct {
		name string
		opts Options
		want []string
	}{
		{
			name: "defaults: stable rules, sorted by file, line, ID",
			want: []string{"NS-A-001@a/config.toml:5", "NS-B-001@a/config.toml:5", "NS-D-001@b/secrets.toml:2", "parse-error@c/compose.yml:3"},
		},
		{
			name: "experimental",
			opts: Options{Experimental: true},
			want: []string{"NS-C-001@a/config.toml:1", "NS-A-001@a/config.toml:5", "NS-B-001@a/config.toml:5", "NS-D-001@b/secrets.toml:2", "parse-error@c/compose.yml:3"},
		},
		{
			name: "enable one experimental rule, disable a stable one",
			opts: Options{Enable: map[string]bool{"NS-C-001": true}, Disable: map[string]bool{"NS-A-001": true}},
			want: []string{"NS-C-001@a/config.toml:1", "NS-B-001@a/config.toml:5", "NS-D-001@b/secrets.toml:2", "parse-error@c/compose.yml:3"},
		},
		{
			name: "minimum severity high",
			opts: Options{MinSeverity: rules.SeverityHigh},
			want: []string{"NS-B-001@a/config.toml:5", "NS-D-001@b/secrets.toml:2", "parse-error@c/compose.yml:3"},
		},
		{
			name: "minimum severity critical drops parse errors",
			opts: Options{MinSeverity: rules.SeverityCritical},
			want: []string{"NS-D-001@b/secrets.toml:2"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ids(Run(targets, problems, all, tc.opts))
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("got  %v\nwant %v", got, tc.want)
			}
		})
	}
}

func TestRunIsDeterministic(t *testing.T) {
	all := []rules.Rule{
		fakeRule{"NS-Z-001", rules.SeverityHigh, rules.Stable, model.KindConfig, 1},
		fakeRule{"NS-Y-001", rules.SeverityHigh, rules.Stable, model.KindConfig, 1},
	}
	var targets []*model.Target
	for i := 9; i >= 0; i-- {
		targets = append(targets, &model.Target{Kind: model.KindConfig, Path: fmt.Sprintf("f%d.toml", i)})
	}
	first := fmt.Sprint(ids(Run(targets, nil, all, Options{})))
	for i := 0; i < 20; i++ {
		if got := fmt.Sprint(ids(Run(targets, nil, all, Options{}))); got != first {
			t.Fatalf("run %d differs:\n%s\n%s", i, got, first)
		}
	}
}

func TestSortTieBreakers(t *testing.T) {
	f := []rules.Finding{
		{RuleID: "B", Message: "x", Location: model.Location{File: "a", Line: 1, Column: 2}},
		{RuleID: "B", Message: "w", Location: model.Location{File: "a", Line: 1, Column: 2}},
		{RuleID: "A", Message: "z", Location: model.Location{File: "a", Line: 1, Column: 2}},
		{RuleID: "C", Message: "a", Location: model.Location{File: "a", Line: 1, Column: 1}},
	}
	Sort(f)
	got := ""
	for _, x := range f {
		got += x.RuleID + x.Message + " "
	}
	if got != "Ca Az Bw Bx " {
		t.Errorf("order = %q", got)
	}
}

type panickyRule struct{ fakeRule }

func (panickyRule) Check(*model.Target) []rules.Finding {
	panic("secret-value-in-panic")
}

func TestRuleCrashIsContained(t *testing.T) {
	all := []rules.Rule{
		panickyRule{fakeRule{"NS-P-001", rules.SeverityLow, rules.Stable, model.KindConfig, 1}},
		fakeRule{"NS-OK-001", rules.SeverityLow, rules.Stable, model.KindConfig, 2},
	}
	got := Run([]*model.Target{{Kind: model.KindConfig, Path: "c.toml"}}, nil, all, Options{})
	if fmt.Sprint(ids(got)) != "[internal-error@c.toml:0 NS-OK-001@c.toml:2]" {
		t.Fatalf("findings = %v", ids(got))
	}
	if got[0].Severity != rules.SeverityHigh || !strings.Contains(got[0].Message, "NS-P-001") || strings.Contains(got[0].Message, "secret-value") {
		t.Errorf("internal error finding = %+v", got[0])
	}
}
