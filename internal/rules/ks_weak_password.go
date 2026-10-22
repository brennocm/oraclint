package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// ksWeakPassword flags keystore and VRF passwords that fail the node's own
// complexity rule (utils.VerifyPasswordComplexity: at least 16 characters, no
// leading or trailing whitespace). The node enforces it only when creating a
// new keystore, so an existing node keeps running with a weak password
// (core/cmd/key_store_authenticator.go, v2.69.0).
type ksWeakPassword struct{}

// minKeystorePasswordLen is utils.MinRequiredLen in the node.
const minKeystorePasswordLen = 16

var keystorePasswordEnv = map[string]string{
	"CL_PASSWORD_KEYSTORE": "Password.Keystore",
	"CL_PASSWORD_VRF":      "Password.VRF",
}

func (ksWeakPassword) Metadata() Metadata {
	return Metadata{
		ID:          "NS-KS-002",
		Title:       "Weak keystore password",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindSecrets, model.KindEnv, model.KindCompose, model.KindK8s},
		Status:      Stable,
		Remediation: "Use a randomly generated password of at least 16 characters without surrounding whitespace, and change it with the node's keystore password change procedure.",
		References:  []string{refSecrets + "#password", "https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/utils/password.go"},
		CWE:         []string{"CWE-521"},
	}
}

func (r ksWeakPassword) Check(t *model.Target) []Finding {
	var out []Finding
	if t.Kind == model.KindSecrets {
		for _, key := range []string{"Password.Keystore", "Password.VRF"} {
			v := t.TOML.Root.Get(key)
			if v == nil {
				continue
			}
			pw, _ := v.Scalar.(string)
			if problem := passwordProblem(pw); problem != "" {
				out = append(out, newFinding(r.Metadata(), v.Loc, "%s %s", key, problem))
			}
		}
		return out
	}
	for _, e := range envAssignments(t) {
		if _, ok := keystorePasswordEnv[e.Name]; !ok || !e.Literal {
			continue
		}
		if problem := passwordProblem(e.Value); problem != "" {
			out = append(out, newFinding(r.Metadata(), e.Loc, "%s %s", e.Name, problem))
		}
	}
	return out
}

// passwordProblem describes why pw fails the node's complexity rule, or
// returns "". It never includes the password or its exact length.
func passwordProblem(pw string) string {
	switch {
	case pw == "":
		return "" // empty means "not set here"; the node prompts or fails
	case len(pw) < minKeystorePasswordLen:
		return "is shorter than 16 characters"
	case strings.TrimSpace(pw) != pw:
		return "has leading or trailing whitespace"
	default:
		return ""
	}
}
