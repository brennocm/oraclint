// Package suppress applies inline "# oraclint:ignore" directives and the
// .oraclint.yaml configuration file to findings. Every suppression needs a
// written reason, and suppressed findings are marked, not removed.
package suppress

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DefaultConfigFile is read from the working directory when --config-file is
// not given.
const DefaultConfigFile = ".oraclint.yaml"

// maxConfigSize bounds the tool's own config file.
const maxConfigSize = 1 << 20

// Config is the content of .oraclint.yaml.
//
//	disable:
//	  - rule: NS-LOG-001
//	    reason: "debug logging is required on this staging node"
//	ignore:
//	  - rule: NS-WEB-001
//	    paths: ["deploy/staging/**"]
//	    reason: "TLS is terminated at the load balancer"
type Config struct {
	Disable []DisableEntry `yaml:"disable"`
	Ignore  []IgnoreEntry  `yaml:"ignore"`
	// File is where the config was read from, for locations in output.
	File string `yaml:"-"`
}

// DisableEntry turns a rule off everywhere.
type DisableEntry struct {
	Rule   string `yaml:"rule"`
	Reason string `yaml:"reason"`
}

// IgnoreEntry suppresses a rule's findings in matching files.
type IgnoreEntry struct {
	Rule   string   `yaml:"rule"`
	Paths  []string `yaml:"paths"`
	Reason string   `yaml:"reason"`
}

// LoadConfig reads and validates a config file. Unknown keys and entries
// without a reason are errors: a typo must not silently disable nothing (or
// everything).
func LoadConfig(file string, known func(id string) bool) (*Config, error) {
	f, err := os.Open(file) //nolint:gosec // the user chooses the config file
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}
	defer f.Close() //nolint:errcheck // read-only file
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", file, maxConfigSize)
	}

	cfg := &Config{File: filepath.ToSlash(filepath.Clean(file))}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing %s: %w", file, err)
	}
	if err := cfg.validate(known); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return cfg, nil
}

func (c *Config) validate(known func(id string) bool) error {
	for i := range c.Disable {
		e := &c.Disable[i]
		e.Rule = strings.ToUpper(strings.TrimSpace(e.Rule))
		if err := checkEntry("disable", i, e.Rule, e.Reason, known); err != nil {
			return err
		}
	}
	for i := range c.Ignore {
		e := &c.Ignore[i]
		e.Rule = strings.ToUpper(strings.TrimSpace(e.Rule))
		if err := checkEntry("ignore", i, e.Rule, e.Reason, known); err != nil {
			return err
		}
		if len(e.Paths) == 0 {
			return fmt.Errorf("ignore[%d] (%s): paths is required; use disable to turn a rule off everywhere", i, e.Rule)
		}
		for _, p := range e.Paths {
			if _, err := path.Match(p, ""); err != nil {
				return fmt.Errorf("ignore[%d] (%s): invalid path pattern %q", i, e.Rule, p)
			}
		}
	}
	return nil
}

func checkEntry(section string, i int, rule, reason string, known func(string) bool) error {
	switch {
	case rule == "":
		return fmt.Errorf("%s[%d]: rule is required", section, i)
	case known != nil && !known(rule):
		return fmt.Errorf("%s[%d]: unknown rule %q", section, i, rule)
	case strings.TrimSpace(reason) == "":
		return fmt.Errorf("%s[%d] (%s): reason is required", section, i, rule)
	}
	return nil
}

// DisabledRules returns the IDs turned off by the config.
func (c *Config) DisabledRules() map[string]bool {
	out := map[string]bool{}
	if c == nil {
		return out
	}
	for _, e := range c.Disable {
		out[e.Rule] = true
	}
	return out
}

// matchPath reports whether file matches pattern. Both use forward slashes.
// Supported patterns: an exact path, a path.Match glob ("*" stays within one
// directory), and "dir/**" for everything below dir.
func matchPath(pattern, file string) bool {
	pattern = path.Clean(filepath.ToSlash(pattern))
	file = path.Clean(filepath.ToSlash(file))
	if dir, ok := strings.CutSuffix(pattern, "/**"); ok {
		return file == dir || strings.HasPrefix(file, dir+"/")
	}
	ok, err := path.Match(pattern, file)
	return err == nil && ok
}
