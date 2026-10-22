package rules

import "github.com/brennocm/oraclint/internal/model"

// dockerUIExposed flags a node service that publishes the operator UI/API
// port (6688 HTTP, 6689 HTTPS by default) on a non-loopback host interface.
// The node security best practices say to keep 6688 closed to the internet
// and reach it through an SSH tunnel.
type dockerUIExposed struct{}

// operatorPorts are the node's default WebServer.HTTPPort and TLS.HTTPSPort.
var operatorPorts = []int{6688, 6689}

func (dockerUIExposed) Metadata() Metadata {
	return Metadata{
		ID:          "NS-DKR-001",
		Title:       "Operator UI port published on a public interface",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindCompose},
		Status:      Stable,
		Remediation: "Publish the port on loopback only (\"127.0.0.1:6688:6688\") and use an SSH tunnel or VPN to reach it.",
		References:  []string{refBestPractic, refRunningNode},
		CWE:         []string{"CWE-668"},
	}
}

func (r dockerUIExposed) Check(t *model.Target) []Finding {
	var out []Finding
	for _, svc := range composeServices(t) {
		if !svc.isNodeService() {
			continue
		}
		for _, pp := range svc.ports() {
			if isLoopback(pp.HostIP) {
				continue
			}
			for _, port := range operatorPorts {
				if !pp.exposes(port) {
					continue
				}
				where := "all host interfaces"
				if !pp.onAllInterfaces() {
					where = "host interface " + pp.HostIP
				}
				out = append(out, newFinding(r.Metadata(), model.YAMLLocation(t.Path, pp.Node),
					"service %q publishes operator port %d on %s", svc.Name, port, where))
			}
		}
	}
	return out
}
