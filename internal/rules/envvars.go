package rules

import (
	"regexp"
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// envAssignment is one environment variable set by a dotenv file, a compose
// service or a Kubernetes container.
type envAssignment struct {
	Name  string
	Value string
	Loc   model.Location
	// Literal is true when the value is written in the file itself, as
	// opposed to compose "${VAR}" interpolation, a compose pass-through
	// ("- VAR" or "VAR:" with no value) or a Kubernetes valueFrom reference.
	Literal bool
}

// nodeSecretEnvVars are the node's secret environment variables (core/config/
// env/env.go, v2.69.0) plus the Postgres image's password variable, which
// usually holds the same database password.
var nodeSecretEnvVars = []string{
	"CL_DATABASE_URL",
	"CL_DATABASE_BACKUP_URL",
	"CL_PASSWORD_KEYSTORE",
	"CL_PASSWORD_VRF",
	"CL_PYROSCOPE_AUTH_TOKEN",
	"CL_PROMETHEUS_AUTH_TOKEN",
	"CL_THRESHOLD_KEY_SHARE",
	"POSTGRES_PASSWORD",
}

func isNodeSecretEnvVar(name string) bool {
	for _, n := range nodeSecretEnvVars {
		if name == n {
			return true
		}
	}
	return false
}

// interpolation matches compose variable references: ${VAR}, ${VAR:-x}, $VAR.
var interpolation = regexp.MustCompile(`\$\{|\$[A-Za-z_]`)

// defaultOnly matches a value that is exactly one reference with a default:
// ${VAR:-default} or ${VAR-default}.
var defaultOnly = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:?-(.*)\}$`)

// composeValue decides whether a compose environment value is written in the
// file. "$$" is compose's escape for a literal "$". A reference with a default
// (${VAR:-changeme}) counts as literal: the default is committed in the file
// and is what runs whenever VAR is unset.
func composeValue(raw string) (value string, literal bool) {
	unescaped := strings.ReplaceAll(raw, "$$", "")
	if !interpolation.MatchString(unescaped) {
		return strings.ReplaceAll(raw, "$$", "$"), true
	}
	if m := defaultOnly.FindStringSubmatch(raw); m != nil && m[1] != "" && !interpolation.MatchString(m[1]) {
		return m[1], true
	}
	return raw, false
}

// envAssignments lists the environment variables a target sets.
func envAssignments(t *model.Target) []envAssignment {
	switch t.Kind {
	case model.KindEnv:
		out := make([]envAssignment, 0, len(t.Env))
		for _, v := range t.Env {
			out = append(out, envAssignment{Name: v.Name, Value: v.Value, Loc: v.Loc, Literal: true})
		}
		return out
	case model.KindCompose:
		return composeEnv(t)
	case model.KindK8s:
		return k8sEnv(t)
	default:
		return nil
	}
}

func composeEnv(t *model.Target) []envAssignment {
	var out []envAssignment
	for _, svc := range composeServices(t) {
		env := model.MapValue(svc.Node, "environment")
		// Map form: KEY: value
		keys, values := model.MapPairs(env)
		for i := range keys {
			raw, isScalar := model.ScalarString(values[i])
			passThrough := !isScalar || values[i].Tag == "!!null"
			value, literal := composeValue(raw)
			out = append(out, envAssignment{
				Name:    keys[i].Value,
				Value:   value,
				Loc:     model.YAMLLocation(t.Path, keys[i]),
				Literal: !passThrough && literal,
			})
		}
		// List form: - KEY=value, or - KEY to pass the host value through
		for _, item := range model.SeqItems(env) {
			s, _ := model.ScalarString(item)
			name, raw, hasValue := strings.Cut(s, "=")
			value, literal := composeValue(raw)
			out = append(out, envAssignment{
				Name:    name,
				Value:   value,
				Loc:     model.YAMLLocation(t.Path, item),
				Literal: hasValue && literal,
			})
		}
	}
	return out
}

func k8sEnv(t *model.Target) []envAssignment {
	var out []envAssignment
	for _, pod := range podSpecs(t) {
		for _, c := range pod.containers() {
			for _, e := range model.SeqItems(model.MapValue(c.Node, "env")) {
				nameKey, nameNode := model.MapGet(e, "name")
				name, _ := model.ScalarString(nameNode)
				_, valueNode := model.MapGet(e, "value")
				value, hasValue := model.ScalarString(valueNode)
				out = append(out, envAssignment{
					Name:    name,
					Value:   value,
					Loc:     model.YAMLLocation(t.Path, nameKey),
					Literal: hasValue,
				})
			}
		}
	}
	return out
}

// envTrue mirrors how the node reads boolean environment variables:
// env.Var.IsTrue compares the lowercased value with "true", so "1" or "yes"
// do not count (core/config/env/env.go, v2.69.0).
func envTrue(value string) bool {
	return strings.ToLower(value) == "true"
}
