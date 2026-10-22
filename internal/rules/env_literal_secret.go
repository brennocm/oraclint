package rules

import "github.com/brennocm/oraclint/internal/model"

// envLiteralSecret flags node secrets written as literal environment values
// in a compose file or Kubernetes manifest. These files are committed and
// shared, and literal values also show up in `docker inspect`, `kubectl get
// -o yaml` and CI logs.
type envLiteralSecret struct{}

func (envLiteralSecret) Metadata() Metadata {
	return Metadata{
		ID:          "NS-ENV-002",
		Title:       "Node secret as literal environment value",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindCompose, model.KindK8s},
		Status:      Stable,
		Remediation: "Reference the value instead: compose secrets: or ${VAR} interpolation, Kubernetes valueFrom.secretKeyRef; rotate the exposed secret.",
		References:  []string{refSecrets, "https://docs.docker.com/compose/how-tos/use-secrets/", "https://kubernetes.io/docs/concepts/configuration/secret/"},
		CWE:         []string{"CWE-798", "CWE-312"},
	}
}

func (r envLiteralSecret) Check(t *model.Target) []Finding {
	var out []Finding
	for _, e := range envAssignments(t) {
		if isNodeSecretEnvVar(e.Name) && e.Literal && e.Value != "" {
			out = append(out, newFinding(r.Metadata(), e.Loc,
				"%s is set to a literal value in the %s file", e.Name, t.Kind))
		}
	}
	return out
}
