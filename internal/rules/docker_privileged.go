package rules

import (
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/brennocm/oraclint/internal/model"
)

// dockerPrivileged flags container settings that remove isolation from the
// host: privileged mode, host network or PID namespace, capabilities that
// allow escaping or spying on the host, and bind mounts of the Docker socket
// or system directories (mounting docker.sock is equivalent to root on the
// host).
type dockerPrivileged struct{}

var dangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true,
	"SYS_MODULE": true, "DAC_READ_SEARCH": true,
}

func (dockerPrivileged) Metadata() Metadata {
	return Metadata{
		ID:          "NS-DKR-003",
		Title:       "Privileged container or host namespace",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindCompose},
		Status:      Stable,
		Remediation: "Remove privileged, network_mode: host, pid: host, the listed cap_add entries and host mounts of the Docker socket or system directories; the node does not need them.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/", "https://docs.docker.com/engine/security/"},
		CWE:         []string{"CWE-250"},
	}
}

func (r dockerPrivileged) Check(t *model.Target) []Finding {
	m := r.Metadata()
	var out []Finding
	for _, svc := range composeServices(t) {
		if key, v := model.MapGet(svc.Node, "privileged"); model.IsTrue(v) {
			out = append(out, newFinding(m, model.YAMLLocation(t.Path, key),
				"service %q runs privileged, which gives it full access to the host", svc.Name))
		}
		for _, field := range []string{"network_mode", "pid"} {
			key, v := model.MapGet(svc.Node, field)
			if s, _ := model.ScalarString(v); s == "host" {
				out = append(out, newFinding(m, model.YAMLLocation(t.Path, key),
					"service %q uses %s: host and shares the host's namespace", svc.Name, field))
			}
		}
		for _, v := range model.SeqItems(model.MapValue(svc.Node, "volumes")) {
			if src := bindSource(v); isDangerousHostPath(src) {
				out = append(out, newFinding(m, model.YAMLLocation(t.Path, v),
					"service %q mounts host path %s, which gives it control of the host", svc.Name, src))
			}
		}
		for _, c := range model.SeqItems(model.MapValue(svc.Node, "cap_add")) {
			s, _ := model.ScalarString(c)
			capName := strings.TrimPrefix(strings.ToUpper(s), "CAP_")
			if dangerousCaps[capName] {
				out = append(out, newFinding(m, model.YAMLLocation(t.Path, c),
					"service %q adds capability %s", svc.Name, capName))
			}
		}
	}
	return out
}

// bindSource returns the host path of a compose volume entry, or "" for named
// volumes. Short syntax: "SOURCE:TARGET[:MODE]"; long syntax: {type: bind,
// source: ...}.
func bindSource(v *yaml.Node) string {
	if v.Kind == yaml.MappingNode {
		src, _ := model.ScalarString(model.MapValue(v, "source"))
		return src
	}
	s, _ := model.ScalarString(v)
	src, _, _ := strings.Cut(s, ":")
	return src
}
