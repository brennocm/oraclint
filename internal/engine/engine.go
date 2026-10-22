// Package engine runs rules over targets, applies filters and returns findings
// in a deterministic order.
package engine

import (
	"sort"
	"strings"

	"github.com/brennocm/oraclint/internal/model"
	"github.com/brennocm/oraclint/internal/redact"
	"github.com/brennocm/oraclint/internal/rules"
)

// ParseErrorRuleID is the pseudo rule ID used for files that could not be
// scanned. It is reported like a finding so a broken file never passes CI
// silently.
const ParseErrorRuleID = "parse-error"

// Options select which rules run and which findings are kept.
type Options struct {
	MinSeverity  rules.Severity
	Experimental bool            // run experimental rules
	Enable       map[string]bool // rule IDs to run even if experimental
	Disable      map[string]bool // rule IDs never to run
}

// Select returns the rules that should run with these options.
func Select(all []rules.Rule, opts Options) []rules.Rule {
	var selected []rules.Rule
	for _, r := range all {
		m := r.Metadata()
		if opts.Disable[m.ID] {
			continue
		}
		if m.Status == rules.Experimental && !opts.Experimental && !opts.Enable[m.ID] {
			continue
		}
		selected = append(selected, r)
	}
	return selected
}

// Run checks every target with every applicable rule. Problems from the
// loader become parse-error findings. Every message is redacted.
func Run(targets []*model.Target, problems []*model.ParseError, all []rules.Rule, opts Options) []rules.Finding {
	var findings []rules.Finding
	for _, p := range problems {
		findings = append(findings, rules.Finding{
			RuleID:      ParseErrorRuleID,
			Severity:    rules.SeverityHigh,
			Title:       "File could not be scanned",
			Message:     p.Msg,
			Location:    p.Loc,
			Remediation: "Fix the file so it parses, or exclude it from the scan.",
		})
	}

	selected := Select(all, opts)
	for _, t := range targets {
		for _, r := range selected {
			if r.Metadata().AppliesTo(t.Kind) {
				findings = append(findings, r.Check(t)...)
			}
		}
	}

	// Safety net: whatever a rule wrote, mask every known secret and
	// secret-looking pattern before the finding leaves the engine.
	var redactor redact.Redactor
	for _, t := range targets {
		redact.Collect(&redactor, t)
	}

	kept := findings[:0]
	for _, f := range findings {
		if f.Severity >= opts.MinSeverity {
			f.Message = redactor.Apply(f.Message)
			kept = append(kept, f)
		}
	}
	Sort(kept)
	return kept
}

// Sort orders findings by file, line, column, rule ID and message, so the
// same input always produces byte-identical output.
func Sort(findings []rules.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.Location.Column != b.Location.Column {
			return a.Location.Column < b.Location.Column
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return strings.Compare(a.Message, b.Message) < 0
	})
}
