package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/brennocm/oraclint/internal/redact"
	"github.com/brennocm/oraclint/internal/rules"
)

// ANSI escape codes. Written out by hand instead of using a color library:
// five constants do not justify a dependency (see ADR 0008).
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiCyan   = "\x1b[36m"
	ansiPurple = "\x1b[35m"
)

var severityColor = map[rules.Severity]string{
	rules.SeverityCritical: ansiBold + ansiPurple,
	rules.SeverityHigh:     ansiBold + ansiRed,
	rules.SeverityMedium:   ansiYellow,
	rules.SeverityLow:      ansiBlue,
	rules.SeverityInfo:     ansiCyan,
}

// textWriter wraps a writer and remembers the first error, so the rendering
// code is not cluttered with an error check after every line.
type textWriter struct {
	w     *bufio.Writer
	color bool
	err   error
}

func (tw *textWriter) printf(format string, args ...any) {
	if tw.err != nil {
		return
	}
	_, tw.err = fmt.Fprintf(tw.w, format, args...)
}

func (tw *textWriter) paint(code, s string) string {
	if !tw.color || code == "" {
		return s
	}
	return code + s + ansiReset
}

func writeText(w io.Writer, rep Report, opts Options) error {
	tw := &textWriter{w: bufio.NewWriter(w), color: opts.Color}

	currentFile := ""
	for _, f := range rep.Findings {
		if f.Suppression != nil {
			continue // listed in JSON/SARIF; only counted here
		}
		if f.Location.File != currentFile {
			if currentFile != "" {
				tw.printf("\n")
			}
			currentFile = f.Location.File
			// File names come from the scanned tree and may contain
			// escape sequences; messages are already sanitized by the engine.
			tw.printf("%s\n", tw.paint(ansiBold, redact.Printable(currentFile)))
		}
		pos := "-"
		if f.Location.Line > 0 {
			pos = fmt.Sprintf("%d:%d", f.Location.Line, max(f.Location.Column, 1))
		}
		sev := strings.ToUpper(f.Severity.String())
		tw.printf("  %-7s %s %-12s %s\n",
			pos,
			tw.paint(severityColor[f.Severity], fmt.Sprintf("%-8s", sev)),
			f.RuleID,
			f.Message)
		tw.printf("  %s\n", tw.paint(ansiDim, "        fix: "+f.Remediation))
	}

	if !opts.Quiet {
		writeSummary(tw, rep)
	}

	if tw.err != nil {
		return tw.err
	}
	return tw.w.Flush()
}

func writeSummary(tw *textWriter, rep Report) {
	defer func() {
		for _, d := range rep.Disabled {
			tw.printf("%s %s disabled by %s: %s\n", tw.paint(ansiYellow, "!"), d.ID,
				redact.Printable(d.Source), redact.Printable(d.Reason))
		}
		for _, e := range rep.Excluded {
			tw.printf("%s %s excluded by %s: %s\n", tw.paint(ansiYellow, "!"), redact.Printable(e.Pattern),
				redact.Printable(e.Source), redact.Printable(e.Reason))
		}
	}()
	c := countBySeverity(rep.Findings)
	suppressed := ""
	if n := countSuppressed(rep.Findings); n > 0 {
		suppressed = fmt.Sprintf(" (%d suppressed)", n)
	}
	if c.Total() == 0 {
		tw.printf("%s No issues found in %s%s.\n", tw.paint(ansiBold, "✓"), plural(rep.FilesScanned, "file"), suppressed)
		return
	}
	tw.printf("\n%s in %s: %d critical, %d high, %d medium, %d low, %d info%s\n",
		tw.paint(ansiBold, plural(c.Total(), "finding")), plural(rep.FilesScanned, "file"),
		c.Critical, c.High, c.Medium, c.Low, c.Info, suppressed)
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
