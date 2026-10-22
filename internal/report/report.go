// Package report renders scan results as text, JSON or SARIF.
//
// Reporters receive findings that the engine has already redacted. They add
// no data from scanned files of their own, only rule metadata and positions.
package report

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/brennocm/oraclint/internal/rules"
)

// Format names accepted by --format.
const (
	FormatText  = "text"
	FormatJSON  = "json"
	FormatSARIF = "sarif"
)

// InformationURI is the project home page, used in SARIF and JSON output.
const InformationURI = "https://github.com/brennocm/oraclint"

// Report is everything a reporter needs.
type Report struct {
	ToolVersion string
	// Rules is every rule that ran, used for SARIF's rule catalog.
	Rules    []rules.Metadata
	Findings []rules.Finding
	// FilesScanned is the number of files that were analyzed.
	FilesScanned int
	// BaseDir makes absolute file paths relative in SARIF output. Empty
	// means paths are used as they are.
	BaseDir string
	// Disabled lists rules turned off by the oraclint config file, so a
	// config that silences rules is always visible in the output.
	Disabled []DisabledRule
	// Excluded lists path patterns excluded by the oraclint config file.
	Excluded []ExcludedPath
}

// ExcludedPath is a path pattern removed from the scan by configuration.
type ExcludedPath struct {
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
	Source  string `json:"source"`
}

// DisabledRule is a rule switched off by configuration, with the reason.
type DisabledRule struct {
	ID     string `json:"rule_id"`
	Reason string `json:"reason"`
	Source string `json:"source"`
}

// Options tune the text reporter.
type Options struct {
	Color bool
	// Quiet omits the summary line, printing only findings.
	Quiet bool
}

// Write renders rep in the given format.
func Write(w io.Writer, format string, rep Report, opts Options) error {
	switch format {
	case FormatText:
		return writeText(w, rep, opts)
	case FormatJSON:
		return writeJSON(w, rep)
	case FormatSARIF:
		return writeSARIF(w, rep)
	default:
		return fmt.Errorf("unknown format %q (want text, json or sarif)", format)
	}
}

// Counts summarizes findings per severity.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Total returns the sum of all severities.
func (c Counts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Info
}

// countBySeverity counts active (not suppressed) findings.
func countBySeverity(findings []rules.Finding) Counts {
	var c Counts
	for _, f := range findings {
		if f.Suppression != nil {
			continue
		}
		switch f.Severity {
		case rules.SeverityCritical:
			c.Critical++
		case rules.SeverityHigh:
			c.High++
		case rules.SeverityMedium:
			c.Medium++
		case rules.SeverityLow:
			c.Low++
		case rules.SeverityInfo:
			c.Info++
		}
	}
	return c
}

func countSuppressed(findings []rules.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Suppression != nil {
			n++
		}
	}
	return n
}

// relativePath returns path relative to base with forward slashes, when path
// is absolute and inside base. Otherwise path is returned unchanged.
func relativePath(base, path string) string {
	if base == "" || !filepath.IsAbs(filepath.FromSlash(path)) {
		return filepath.ToSlash(path)
	}
	rel, err := filepath.Rel(base, filepath.FromSlash(path))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
