// Package engine runs rules over targets, applies filters and returns findings
// in a deterministic order.
package engine

import (
	"sort"
	"strings"

	"github.com/brennocm/oraclint/internal/model"
	"github.com/brennocm/oraclint/internal/redact"
	"github.com/brennocm/oraclint/internal/rules"
	"github.com/brennocm/oraclint/internal/suppress"
)

// Options select which rules run and which findings are kept.
type Options struct {
	MinSeverity  rules.Severity
	Experimental bool            // run experimental rules
	Enable       map[string]bool // rule IDs to run even if experimental
	Disable      map[string]bool // rule IDs never to run
	// Suppressions from .oraclint.yaml; nil when there is no config file.
	// Inline directives come with the targets.
	Suppressions *suppress.Config
	// IgnoreSuppressions disables inline directives too (audit mode, for
	// scanning content whose suppressions are not trusted).
	IgnoreSuppressions bool
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
// loader become parse-error findings. Suppressions are applied (findings are
// marked, not removed) and every message is redacted.
func Run(targets []*model.Target, problems []*model.ParseError, all []rules.Rule, opts Options) []rules.Finding {
	var findings []rules.Finding
	for _, p := range problems {
		findings = append(findings, rules.Finding{
			RuleID:      rules.ParseError.ID,
			Severity:    rules.ParseError.Severity,
			Title:       rules.ParseError.Title,
			Message:     p.Msg,
			Location:    p.Loc,
			Remediation: rules.ParseError.Remediation,
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

	known := make(map[string]bool, len(all))
	for _, r := range all {
		known[r.Metadata().ID] = true
	}
	if !opts.IgnoreSuppressions {
		findings = suppress.Apply(findings, targets, opts.Suppressions, func(id string) bool { return known[id] })
	}

	// Safety net: whatever a rule wrote, mask every known secret and
	// secret-looking pattern before the finding leaves the engine, and
	// neutralize control characters copied from scanned files.
	var redactor redact.Redactor
	for _, t := range targets {
		redact.Collect(&redactor, t)
	}

	kept := findings[:0]
	for _, f := range findings {
		if f.Severity >= opts.MinSeverity {
			f.Message = redact.Printable(redactor.Apply(f.Message))
			if f.Suppression != nil {
				s := *f.Suppression // copy: never mutate shared state
				s.Reason = redact.Printable(redactor.Apply(s.Reason))
				f.Suppression = &s
			}
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
