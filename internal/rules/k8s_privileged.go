package rules

import "github.com/brennocm/oraclint/internal/model"

// k8sPrivileged flags pods that share host namespaces and containers that run
// privileged. Either one lets a compromised container reach the node (host)
// and every other workload on it.
type k8sPrivileged struct{}

func (k8sPrivileged) Metadata() Metadata {
	return Metadata{
		ID:          "NS-K8S-001",
		Title:       "Privileged pod or host namespace",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindK8s},
		Status:      Stable,
		Remediation: "Remove hostNetwork, hostPID, hostIPC and securityContext.privileged.",
		References:  []string{"https://kubernetes.io/docs/concepts/security/pod-security-standards/"},
		CWE:         []string{"CWE-250"},
	}
}

func (r k8sPrivileged) Check(t *model.Target) []Finding {
	m := r.Metadata()
	var out []Finding
	for _, pod := range podSpecs(t) {
		for _, field := range []string{"hostNetwork", "hostPID", "hostIPC"} {
			if key, v := model.MapGet(pod.Spec, field); model.IsTrue(v) {
				out = append(out, newFinding(m, model.YAMLLocation(t.Path, key),
					"%s %q sets %s: true", pod.Kind, pod.Name, field))
			}
		}
		for _, c := range pod.containers() {
			key, v := model.MapGet(model.MapValue(c.Node, "securityContext"), "privileged")
			if model.IsTrue(v) {
				out = append(out, newFinding(m, model.YAMLLocation(t.Path, key),
					"%s %q container %q runs privileged", pod.Kind, pod.Name, c.Name))
			}
		}
	}
	return out
}
