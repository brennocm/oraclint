package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// k8sSecurityContext flags containers missing the baseline hardening of the
// Kubernetes "restricted" profile: allowPrivilegeEscalation: false,
// runAsNonRoot: true (container or pod level) and readOnlyRootFilesystem:
// true. One finding per container lists everything that is missing.
type k8sSecurityContext struct{}

func (k8sSecurityContext) Metadata() Metadata {
	return Metadata{
		ID:          "NS-K8S-002",
		Title:       "Container securityContext not hardened",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindK8s},
		Status:      Stable,
		Remediation: "Set allowPrivilegeEscalation: false, runAsNonRoot: true and readOnlyRootFilesystem: true (mount a writable volume for the node's root directory).",
		References:  []string{"https://kubernetes.io/docs/concepts/security/pod-security-standards/", "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"},
		CWE:         []string{"CWE-250"},
	}
}

func (r k8sSecurityContext) Check(t *model.Target) []Finding {
	var out []Finding
	for _, pod := range podSpecs(t) {
		podNonRoot := model.MapValue(model.MapValue(pod.Spec, "securityContext"), "runAsNonRoot")
		for _, c := range pod.containers() {
			sc := model.MapValue(c.Node, "securityContext")
			var missing []string
			if v := model.MapValue(sc, "allowPrivilegeEscalation"); v == nil || model.IsTrue(v) {
				missing = append(missing, "allowPrivilegeEscalation: false")
			}
			nonRoot := model.MapValue(sc, "runAsNonRoot")
			if nonRoot == nil {
				nonRoot = podNonRoot // container value overrides the pod value
			}
			if !model.IsTrue(nonRoot) {
				missing = append(missing, "runAsNonRoot: true")
			}
			if !model.IsTrue(model.MapValue(sc, "readOnlyRootFilesystem")) {
				missing = append(missing, "readOnlyRootFilesystem: true")
			}
			if len(missing) > 0 {
				out = append(out, newFinding(r.Metadata(), model.YAMLLocation(t.Path, c.Node),
					"%s %q container %q is missing %s", pod.Kind, pod.Name, c.Name, strings.Join(missing, ", ")))
			}
		}
	}
	return out
}
