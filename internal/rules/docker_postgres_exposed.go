package rules

import "github.com/brennocm/oraclint/internal/model"

// dockerPostgresExposed flags a Postgres service that publishes 5432 beyond
// loopback. The node talks to its database over the compose network and needs
// no published port; publishing it exposes the node's keys and state to
// password guessing (Docker also bypasses host firewalls such as ufw for
// published ports).
type dockerPostgresExposed struct{}

func (dockerPostgresExposed) Metadata() Metadata {
	return Metadata{
		ID:          "NS-DKR-002",
		Title:       "Postgres port published to the host network",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindCompose},
		Status:      Stable,
		Remediation: "Remove the ports: entry of the database service (the node reaches it over the compose network), or bind it to 127.0.0.1.",
		References:  []string{refRunningNode, refBestPractic},
		CWE:         []string{"CWE-668"},
	}
}

func (r dockerPostgresExposed) Check(t *model.Target) []Finding {
	var out []Finding
	for _, svc := range composeServices(t) {
		if !svc.isPostgresService() {
			continue
		}
		for _, pp := range svc.ports() {
			if pp.exposes(5432) && !isLoopback(pp.HostIP) {
				out = append(out, newFinding(r.Metadata(), model.YAMLLocation(t.Path, pp.Node),
					"database service %q publishes Postgres port 5432 outside the host", svc.Name))
			}
		}
	}
	return out
}
