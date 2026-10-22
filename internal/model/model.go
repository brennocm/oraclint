// Package model holds the parsed, position-aware representation of every file
// oraclint understands. Rules only ever see these types, never raw bytes.
package model

import (
	"fmt"
	"io/fs"

	"go.yaml.in/yaml/v3"
)

// Kind identifies what a scanned file is.
type Kind int

// The file kinds oraclint understands.
const (
	KindConfig  Kind = iota + 1 // node config.toml
	KindSecrets                 // node secrets.toml
	KindCompose                 // docker-compose file
	KindK8s                     // Kubernetes manifests (one or more YAML documents)
	KindEnv                     // dotenv file
)

// String returns the lowercase name used in CLI flags and output.
func (k Kind) String() string {
	switch k {
	case KindConfig:
		return "config"
	case KindSecrets:
		return "secrets"
	case KindCompose:
		return "compose"
	case KindK8s:
		return "k8s"
	case KindEnv:
		return "env"
	default:
		return fmt.Sprintf("kind(%d)", int(k))
	}
}

// Location points at a place in a scanned file. Line and Column start at 1.
// A zero Line means "the file as a whole".
type Location struct {
	File   string
	Line   int
	Column int
}

// String formats the location as file:line:column, omitting unknown parts.
func (l Location) String() string {
	switch {
	case l.Line == 0:
		return l.File
	case l.Column == 0:
		return fmt.Sprintf("%s:%d", l.File, l.Line)
	default:
		return fmt.Sprintf("%s:%d:%d", l.File, l.Line, l.Column)
	}
}

// Target is one unit of analysis handed to the rules. Exactly one of TOML,
// YAML or Env is set, depending on Kind.
type Target struct {
	Kind Kind
	// Path is the display path of the (first) file, relative to the scan root.
	Path string
	// Files lists every file that contributed to this target, in merge order.
	// It has more than one element only for merged config files.
	Files []string
	// Mode is the permission bits of the file, used by filesystem rules.
	// It is zero when unknown (for example for merged targets).
	Mode fs.FileMode

	TOML *TOMLDoc     // KindConfig, KindSecrets
	YAML []*yaml.Node // KindCompose (one document), KindK8s (one per document)
	Env  []EnvVar     // KindEnv

	// Directives are the "# oraclint:ignore" comments found in the files of
	// this target.
	Directives []Directive
}

// Directive is an inline "# oraclint:ignore RULE-ID reason=\"...\"" comment.
// It applies to findings on its own line or on the line below it.
type Directive struct {
	Loc     Location
	RuleIDs []string
	Reason  string
	// Problem explains why the directive is invalid ("" when valid).
	Problem string
}

// ParseError describes a file that could not be parsed. It never contains
// content from the file other than its position.
type ParseError struct {
	Loc Location
	Msg string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: %s", e.Loc, e.Msg)
}
