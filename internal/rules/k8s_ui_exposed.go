package rules

import (
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/brennocm/oraclint/internal/model"
)

// k8sUIExposed flags a Service of type LoadBalancer or NodePort that exposes
// the operator UI/API port outside the cluster.
type k8sUIExposed struct{}

func (k8sUIExposed) Metadata() Metadata {
	return Metadata{
		ID:          "NS-K8S-004",
		Title:       "Operator UI exposed by a Kubernetes Service",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindK8s},
		Status:      Stable,
		Remediation: "Use a ClusterIP Service and reach the UI with kubectl port-forward, a VPN or an authenticated ingress restricted to operators.",
		References:  []string{refBestPractic, "https://kubernetes.io/docs/concepts/services-networking/service/"},
		CWE:         []string{"CWE-668"},
	}
}

func (r k8sUIExposed) Check(t *model.Target) []Finding {
	var out []Finding
	for _, doc := range t.YAML {
		if kind, _ := model.ScalarString(model.MapValue(doc, "kind")); kind != "Service" {
			continue
		}
		name, _ := model.ScalarString(model.MapValue(model.MapValue(doc, "metadata"), "name"))
		spec := model.MapValue(doc, "spec")
		svcType, _ := model.ScalarString(model.MapValue(spec, "type"))
		if svcType != "LoadBalancer" && svcType != "NodePort" {
			continue
		}
		for _, p := range model.SeqItems(model.MapValue(spec, "ports")) {
			if port, ok := servicePortMatches(p); ok {
				out = append(out, newFinding(r.Metadata(), model.YAMLLocation(t.Path, p),
					"Service %q of type %s exposes operator port %d outside the cluster", name, svcType, port))
			}
		}
	}
	return out
}

// servicePortMatches reports whether a Service port entry targets an
// operator port, through either port or a numeric targetPort.
func servicePortMatches(p *yaml.Node) (int, bool) {
	for _, field := range []string{"targetPort", "port"} {
		s, _ := model.ScalarString(model.MapValue(p, field))
		n, err := strconv.Atoi(s)
		if err != nil {
			continue
		}
		for _, op := range operatorPorts {
			if n == op {
				return n, true
			}
		}
	}
	return 0, false
}
