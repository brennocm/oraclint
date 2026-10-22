package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// dockerPrivileged flags container settings that remove isolation from the
// host: privileged mode, host network or PID namespace, and capabilities that
// allow escaping or spying on the host.
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
		Remediation: "Remove privileged, network_mode: host, pid: host and the listed cap_add entries; the node does not need them.",
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
