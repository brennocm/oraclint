package rules

import "github.com/brennocm/oraclint/internal/model"

// envFileSecrets flags node secrets stored in a dotenv file inside the
// scanned tree. Compose reads .env automatically, which makes it a common
// place for CL_PASSWORD_KEYSTORE and friends, and a common file to commit by
// accident.
type envFileSecrets struct{}

func (envFileSecrets) Metadata() Metadata {
	return Metadata{
		ID:          "NS-ENV-001",
		Title:       "Node secrets in a dotenv file",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindEnv},
		Status:      Stable,
		Remediation: "Keep the file out of version control (.gitignore) and outside the repository, or use Docker/Kubernetes secrets.",
		References:  []string{refSecrets, "https://docs.docker.com/compose/how-tos/use-secrets/"},
		CWE:         []string{"CWE-312", "CWE-538"},
	}
}

func (r envFileSecrets) Check(t *model.Target) []Finding {
	var out []Finding
	for _, e := range envAssignments(t) {
		if isNodeSecretEnvVar(e.Name) && e.Value != "" {
			out = append(out, newFinding(r.Metadata(), e.Loc,
				"%s is set in a dotenv file inside the scanned tree", e.Name))
		}
	}
	return out
}
