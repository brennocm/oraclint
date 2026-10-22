// Package rules defines the Rule interface and every built-in rule.
//
// Each rule lives in its own file, implements Rule, and is listed in
// registry.go. Rules are pure functions of a model.Target: no I/O, no network,
// no global state.
package rules

import (
	"fmt"
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// Severity of a finding. The zero value is invalid on purpose, so a rule that
// forgets to set it is caught by the registry tests.
type Severity int

// Severities, from least to most severe. Their order is used for filtering.
const (
	SeverityInfo Severity = iota + 1
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// String returns the lowercase name used in flags and output.
func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// ParseSeverity converts a name such as "high" into a Severity.
func ParseSeverity(name string) (Severity, error) {
	for s, n := range severityNames {
		if strings.EqualFold(name, n) {
			return s, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", name)
}

// Status tells whether a rule runs by default.
type Status int

// Rule statuses.
const (
	// Stable rules run by default.
	Stable Status = iota + 1
	// Experimental rules run only with --experimental or --enable.
	Experimental
)

func (s Status) String() string {
	if s == Experimental {
		return "experimental"
	}
	return "stable"
}

// Metadata describes a rule. It is static: it never depends on the target.
type Metadata struct {
	ID          string
	Title       string
	Severity    Severity
	Targets     []model.Kind
	Status      Status
	Remediation string   // one-line fix, shown with every finding
	References  []string // links to the official node docs or source
	CWE         []string // e.g. "CWE-319"
}

// Finding is one problem found in one place.
//
// Message must never contain a secret value: rules describe *where* and *what*
// (key names, hosts), and the engine additionally passes every message
// through the redact package as a safety net.
type Finding struct {
	RuleID      string
	Severity    Severity
	Title       string
	Message     string
	Location    model.Location
	Remediation string
	// Suppression is set when the finding was suppressed. Suppressed
	// findings are kept (and shown as such in JSON and SARIF) rather than
	// dropped, so suppressions stay reviewable.
	Suppression *Suppression
}

// Suppression records why a finding was suppressed.
type Suppression struct {
	Kind   string // SuppressionInline or SuppressionConfig
	Reason string
	Source model.Location // the directive or config entry
}

// Suppression kinds.
const (
	SuppressionInline = "inline"
	SuppressionConfig = "config"
)

// Rule is implemented by every check. The interface is deliberately small:
// static metadata plus a pure check function.
type Rule interface {
	Metadata() Metadata
	Check(t *model.Target) []Finding
}

// ParseError describes the pseudo rule used for files that could not be
// scanned. It is reported like a finding so a broken file never passes CI
// silently, and it has a SARIF rule entry like any other rule.
var ParseError = Metadata{
	ID:          "parse-error",
	Title:       "File could not be scanned",
	Severity:    SeverityHigh,
	Status:      Stable,
	Remediation: "Fix the file so it parses, or exclude it from the scan.",
}

// InternalError describes the pseudo rule reported when a rule fails (a bug
// in oraclint). It is high severity so the build fails instead of passing
// with a silently skipped check.
var InternalError = Metadata{
	ID:          "internal-error",
	Title:       "Rule failed",
	Severity:    SeverityHigh,
	Status:      Stable,
	Remediation: "This is a bug in oraclint; please report it with the oraclint version (do not include secrets).",
}

// InvalidSuppression describes the pseudo rule reported for an
// "oraclint:ignore" directive that cannot be honored (no reason, unknown rule).
var InvalidSuppression = Metadata{
	ID:          "invalid-suppression",
	Title:       "Invalid suppression directive",
	Severity:    SeverityInfo,
	Status:      Stable,
	Remediation: `Use "# oraclint:ignore RULE-ID reason=\"why this is acceptable\"" with an existing rule ID.`,
}

// newFinding fills the rule-level fields of a Finding from its metadata.
func newFinding(m Metadata, loc model.Location, format string, args ...any) Finding {
	return Finding{
		RuleID:      m.ID,
		Severity:    m.Severity,
		Title:       m.Title,
		Message:     fmt.Sprintf(format, args...),
		Location:    loc,
		Remediation: m.Remediation,
	}
}

// AppliesTo reports whether the rule checks targets of kind k.
func (m Metadata) AppliesTo(k model.Kind) bool {
	for _, t := range m.Targets {
		if t == k {
			return true
		}
	}
	return false
}
