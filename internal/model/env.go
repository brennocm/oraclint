package model

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// EnvVar is one assignment in a dotenv file.
type EnvVar struct {
	Name  string
	Value string
	Loc   Location
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// maxEnvLine bounds the length of a single line. Longer lines are a sign the
// file is not a dotenv file.
const maxEnvLine = 1 << 20

// ParseEnv parses a dotenv file. It supports the common subset understood by
// docker compose: comments, blank lines, an optional "export " prefix, and
// single- or double-quoted values on one line. Lines that are not
// assignments are ignored rather than rejected, because dotenv dialects vary.
func ParseEnv(file string, data []byte) ([]EnvVar, error) {
	data = bytes.TrimPrefix(data, utf8BOM)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxEnvLine)

	var vars []EnvVar
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		name, value, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !found || !envName.MatchString(name) {
			continue
		}
		vars = append(vars, EnvVar{
			Name:  name,
			Value: envValue(strings.TrimSpace(value)),
			Loc:   Location{File: file, Line: lineNo, Column: 1},
		})
	}
	if err := sc.Err(); err != nil {
		return nil, &ParseError{Loc: Location{File: file, Line: lineNo + 1}, Msg: "invalid dotenv file: line too long"}
	}
	return vars, nil
}

// envValue strips quotes and trailing comments from a raw value.
func envValue(raw string) string {
	if len(raw) >= 1 && (raw[0] == '"' || raw[0] == '\'') {
		quote := raw[0]
		if end := strings.IndexByte(raw[1:], quote); end >= 0 {
			return raw[1 : end+1]
		}
		return raw[1:] // unterminated quote: keep the rest
	}
	// Unquoted: " #" starts a comment.
	if i := strings.Index(raw, " #"); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}
