package suppress

import (
	"fmt"

	"github.com/brennocm/oraclint/internal/model"
	"github.com/brennocm/oraclint/internal/rules"
)

// Apply marks findings suppressed by cfg (may be nil) or by the targets'
// inline directives, and returns them together with an invalid-suppression
// finding for every directive that cannot be honored.
//
// An inline directive applies to findings on its own line or on the next
// line, in the same file. Findings that concern a whole file (no line) can
// only be suppressed through the config file.
func Apply(findings []rules.Finding, targets []*model.Target, cfg *Config, known func(id string) bool) []rules.Finding {
	byFile := map[string][]model.Directive{}
	var out []rules.Finding

	for _, t := range targets {
		for _, d := range t.Directives {
			problem := d.Problem
			if problem == "" {
				for _, id := range d.RuleIDs {
					if !known(id) {
						problem = fmt.Sprintf("names unknown rule %q", id)
						break
					}
				}
			}
			if problem != "" {
				out = append(out, invalid(d.Loc, problem))
				continue
			}
			byFile[d.Loc.File] = append(byFile[d.Loc.File], d)
		}
	}

	for _, f := range findings {
		if s := configSuppression(cfg, f); s != nil {
			f.Suppression = s
		} else if s := inlineSuppression(byFile[f.Location.File], f); s != nil {
			f.Suppression = s
		}
		out = append(out, f)
	}
	return out
}

func configSuppression(cfg *Config, f rules.Finding) *rules.Suppression {
	if cfg == nil {
		return nil
	}
	for _, e := range cfg.Ignore {
		if e.Rule != f.RuleID {
			continue
		}
		for _, p := range e.Paths {
			if matchPath(p, f.Location.File) {
				return &rules.Suppression{Kind: rules.SuppressionConfig, Reason: e.Reason, Source: model.Location{File: cfg.File}}
			}
		}
	}
	return nil
}

func inlineSuppression(directives []model.Directive, f rules.Finding) *rules.Suppression {
	if f.Location.Line == 0 {
		return nil
	}
	for _, d := range directives {
		if f.Location.Line != d.Loc.Line && f.Location.Line != d.Loc.Line+1 {
			continue
		}
		for _, id := range d.RuleIDs {
			if id == f.RuleID {
				return &rules.Suppression{Kind: rules.SuppressionInline, Reason: d.Reason, Source: d.Loc}
			}
		}
	}
	return nil
}

func invalid(loc model.Location, problem string) rules.Finding {
	m := rules.InvalidSuppression
	return rules.Finding{
		RuleID:      m.ID,
		Severity:    m.Severity,
		Title:       m.Title,
		Message:     "oraclint:ignore directive " + problem + "; it is not applied",
		Location:    loc,
		Remediation: m.Remediation,
	}
}
