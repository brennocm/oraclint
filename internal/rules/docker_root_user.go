package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// dockerRootUser flags a node service that explicitly runs as root. Official
// production images run as UID 14933 (core/chainlink.Dockerfile, v2.69.0), so
// root only happens when someone overrides it, typically to work around volume
// permission errors. A missing user: is therefore not flagged.
type dockerRootUser struct{}

func (dockerRootUser) Metadata() Metadata {
	return Metadata{
		ID:          "NS-DKR-004",
		Title:       "Node container runs as root",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindCompose},
		Status:      Stable,
		Remediation: "Remove user: root and fix volume ownership for UID:GID 14933:14933 instead.",
		References:  []string{"https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/chainlink.Dockerfile", refConfig + "#rootdir"},
		CWE:         []string{"CWE-250"},
	}
}

func (r dockerRootUser) Check(t *model.Target) []Finding {
	var out []Finding
	for _, svc := range composeServices(t) {
		if !svc.isNodeService() {
			continue
		}
		key, v := model.MapGet(svc.Node, "user")
		user, _ := model.ScalarString(v)
		if isRootUser(user) {
			out = append(out, newFinding(r.Metadata(), model.YAMLLocation(t.Path, key),
				"service %q overrides the image user to run as root", svc.Name))
		}
	}
	return out
}

// isRootUser reports whether a "user[:group]" value selects UID 0.
func isRootUser(spec string) bool {
	user, _, _ := strings.Cut(strings.TrimSpace(spec), ":")
	return user == "root" || user == "0"
}
