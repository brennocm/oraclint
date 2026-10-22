package redact

import (
	"net/url"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/brennocm/oraclint/internal/model"
)

// sensitiveName matches key or variable names whose values are secrets.
var sensitiveName = regexp.MustCompile(`(?i)pass|secret|token|key|credential|auth|private|database_url|dsn|cookie|session|mnemonic|seed`)

// Collect registers every secret value it can find in t with r. It errs on
// the side of registering too much: masking a harmless value only makes a
// message less precise, while missing a secret would leak it.
func Collect(r *Redactor, t *model.Target) {
	if t == nil {
		return
	}
	switch {
	case t.TOML != nil && t.Kind == model.KindSecrets:
		// Everything in a secrets file is a secret.
		walkTOML(t.TOML.Root, "", func(_ string, s string) { addValue(r, s) })
	case t.TOML != nil:
		walkTOML(t.TOML.Root, "", func(path, s string) {
			if sensitiveName.MatchString(path) {
				addValue(r, s)
			}
			// HTTP header strings such as AuditLogger.Headers entries:
			// "Authorization: Bearer xyz".
			if name, value, ok := strings.Cut(s, ":"); ok && sensitiveName.MatchString(name) && !strings.ContainsAny(name, "/ ") {
				addValue(r, value)
			}
			addURLParts(r, s)
		})
	}
	switch t.Kind {
	case model.KindEnv:
		for _, v := range t.Env {
			if sensitiveName.MatchString(v.Name) {
				addValue(r, v.Value)
			}
			addURLParts(r, v.Value)
		}
	case model.KindCompose, model.KindK8s:
		for _, doc := range t.YAML {
			walkYAML(r, doc, "", 0)
		}
	default:
		// config and secrets were handled above
	}
}

func walkTOML(v *model.Value, path string, visit func(path, s string)) {
	if v == nil {
		return
	}
	switch v.Kind {
	case model.TableValue:
		for _, k := range v.SortedKeys() {
			walkTOML(v.Table[k], path+"."+k, visit)
		}
	case model.ArrayValue:
		for _, item := range v.Array {
			walkTOML(item, path, visit)
		}
	case model.ScalarValue:
		if s, ok := v.Scalar.(string); ok {
			visit(path, s)
		}
	}
}

// maxYAMLDepth bounds recursion on hostile, deeply nested YAML.
const maxYAMLDepth = 100

func walkYAML(r *Redactor, n *yaml.Node, key string, depth int) {
	if n == nil || depth > maxYAMLDepth {
		return
	}
	switch n.Kind {
	case yaml.MappingNode:
		keys, values := model.MapPairs(n)
		// Kubernetes env entries are {name: X, value: Y}: the sensitive name
		// is a sibling of the value.
		if name, ok := model.ScalarString(model.MapValue(n, "name")); ok && sensitiveName.MatchString(name) {
			if v, ok := model.ScalarString(model.MapValue(n, "value")); ok {
				addValue(r, v)
			}
		}
		for i := range keys {
			walkYAML(r, values[i], keys[i].Value, depth+1)
		}
	case yaml.SequenceNode:
		for _, item := range model.SeqItems(n) {
			walkYAML(r, item, key, depth+1)
		}
	case yaml.ScalarNode:
		s := n.Value
		// Compose list syntax: "- CL_PASSWORD_KEYSTORE=value".
		if name, value, ok := strings.Cut(s, "="); ok && sensitiveName.MatchString(name) && !strings.ContainsAny(name, " /:") {
			addValue(r, value)
		}
		if sensitiveName.MatchString(key) {
			addValue(r, s)
		}
		addURLParts(r, s)
	}
}

// addValue registers s unless it is a boolean or null keyword, which would
// otherwise mask ordinary words in messages. Numbers are registered: numeric
// passwords and PINs exist.
func addValue(r *Redactor, s string) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "true", "false", "yes", "no", "on", "off", "null", "none":
		return
	}
	r.Add(s)
	addURLParts(r, s)
}

// addURLParts registers the secret parts of a URL: the userinfo password,
// sensitive query values and key-like path segments.
func addURLParts(r *Redactor, s string) {
	if !strings.Contains(s, "://") {
		return
	}
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return
	}
	if pw, ok := u.User.Password(); ok {
		r.Add(pw)
		r.Add(url.QueryEscape(pw)) // the form that appears in the raw URL
	}
	for name, values := range u.Query() {
		if SensitiveParam(name) {
			for _, v := range values {
				r.Add(v)
			}
		}
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if KeyLikeSegment(seg) {
			r.Add(seg)
		}
	}
}
