package model

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// directive matches "# oraclint:ignore <rest>" anywhere on a line.
var directive = regexp.MustCompile(`#\s*oraclint:ignore(?:\s+(.*))?$`)

// reasonAttr matches reason="..." (the reason is mandatory).
var reasonAttr = regexp.MustCompile(`reason\s*=\s*"([^"]*)"`)

// ParseDirectives finds every "# oraclint:ignore" comment in a TOML, YAML or
// dotenv file. All three use "#" comments. Syntax:
//
//	# oraclint:ignore NS-WEB-001,NS-WEB-004 reason="TLS terminated at the load balancer"
//
// Invalid directives are returned with Problem set so they can be reported
// instead of silently ignored.
func ParseDirectives(file string, data []byte) []Directive {
	var out []Directive
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxEnvLine)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		m := directive.FindStringSubmatchIndex(text)
		if m == nil {
			continue
		}
		d := Directive{Loc: Location{File: file, Line: line, Column: m[0] + 1}}
		rest := ""
		if m[2] >= 0 {
			rest = text[m[2]:m[3]]
		}
		ids := rest
		if r := reasonAttr.FindStringSubmatchIndex(rest); r != nil {
			ids = rest[:r[0]]
			d.Reason = strings.TrimSpace(rest[r[2]:r[3]])
		}
		for _, id := range strings.FieldsFunc(ids, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' }) {
			d.RuleIDs = append(d.RuleIDs, strings.ToUpper(id))
		}
		switch {
		case len(d.RuleIDs) == 0:
			d.Problem = "names no rule ID"
		case d.Reason == "":
			d.Problem = `has no reason="..."; a justification is required`
		}
		out = append(out, d)
	}
	return out
}
