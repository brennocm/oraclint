package rules

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/brennocm/oraclint/docs"
)

var ruleIDFormat = regexp.MustCompile(`^NS-[A-Z0-9]+-\d{3}$`)

func TestRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range All() {
		m := r.Metadata()
		t.Run(m.ID, func(t *testing.T) {
			if !ruleIDFormat.MatchString(m.ID) {
				t.Errorf("ID %q does not match %s", m.ID, ruleIDFormat)
			}
			if seen[m.ID] {
				t.Errorf("duplicate ID %s", m.ID)
			}
			seen[m.ID] = true
			if m.Title == "" || m.Remediation == "" {
				t.Error("title and remediation are required")
			}
			if _, ok := severityNames[m.Severity]; !ok {
				t.Errorf("invalid severity %d", m.Severity)
			}
			if m.Status != Stable && m.Status != Experimental {
				t.Errorf("invalid status %d", m.Status)
			}
			if len(m.Targets) == 0 {
				t.Error("rule has no targets")
			}
			if len(m.References) == 0 {
				t.Error("rule must reference the documentation it was verified against")
			}
			for _, ref := range m.References {
				if !strings.HasPrefix(ref, "https://") {
					t.Errorf("reference %q is not an https URL", ref)
				}
			}
			for _, cwe := range m.CWE {
				if !regexp.MustCompile(`^CWE-\d+$`).MatchString(cwe) {
					t.Errorf("bad CWE %q", cwe)
				}
			}
		})
	}
}

func TestEveryRuleHasEmbeddedDoc(t *testing.T) {
	for _, r := range All() {
		m := r.Metadata()
		doc, err := fs.ReadFile(docs.Rules, "rules/"+m.ID+".md")
		if err != nil {
			t.Errorf("%s: missing docs/rules/%s.md", m.ID, m.ID)
			continue
		}
		text := string(doc)
		if !strings.HasPrefix(text, "# "+m.ID+": ") {
			t.Errorf("%s: doc must start with %q", m.ID, "# "+m.ID+": ")
		}
		// The metadata table row must agree with the code.
		row := "| " + m.Severity.String() + " | "
		if !strings.Contains(text, row) || !strings.Contains(text, " | "+m.Status.String()+" | ") {
			t.Errorf("%s: doc table does not match severity %s / status %s", m.ID, m.Severity, m.Status)
		}
		for _, section := range []string{"## Description", "## Why it matters", "## Vulnerable example", "## Fixed example", "## References"} {
			if !strings.Contains(text, section) {
				t.Errorf("%s: doc lacks section %q", m.ID, section)
			}
		}
	}
	// And no orphan docs.
	entries, err := fs.ReadDir(docs.Rules, "rules")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".md")
		if _, ok := ByID(id); !ok {
			t.Errorf("docs/rules/%s has no matching rule", e.Name())
		}
	}
}

func TestByID(t *testing.T) {
	if r, ok := ByID("ns-ks-001"); !ok || r.Metadata().ID != "NS-KS-001" {
		t.Error("ByID should be case-insensitive")
	}
	if _, ok := ByID("NS-NOPE-999"); ok {
		t.Error("unknown ID should not be found")
	}
}

func TestSeverity(t *testing.T) {
	for s, name := range severityNames {
		got, err := ParseSeverity(strings.ToUpper(name))
		if err != nil || got != s || s.String() != name {
			t.Errorf("round trip failed for %s", name)
		}
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("expected error for unknown severity")
	}
	if Severity(0).String() == "" || SeverityCritical <= SeverityHigh || SeverityLow <= SeverityInfo {
		t.Error("severity ordering or fallback name broken")
	}
	if Experimental.String() != "experimental" || Stable.String() != "stable" {
		t.Error("status names")
	}
}
