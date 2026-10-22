package rules

import "github.com/brennocm/oraclint/internal/model"

// telemetryInsecure flags telemetry exported over an insecure connection to a
// non-internal endpoint. The docs describe InsecureConnection as "only
// available in dev mode", but the node does not enforce that (v2.69.0).
type telemetryInsecure struct{}

func (telemetryInsecure) Metadata() Metadata {
	return Metadata{
		ID:          "NS-TEL-001",
		Title:       "Telemetry over an insecure connection",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Remove InsecureConnection / ChipIngressInsecureConnection and configure Telemetry.CACertFile.",
		References:  []string{refConfig + "#telemetry", refValidation},
		CWE:         []string{"CWE-319"},
	}
}

func (r telemetryInsecure) Check(t *model.Target) []Finding {
	doc := t.TOML
	var out []Finding

	if doc.Get("Telemetry.Enabled").IsTrue() {
		insecure := doc.Get("Telemetry.InsecureConnection")
		endpoint, _ := doc.Get("Telemetry.Endpoint").String()
		if host := endpointHost(endpoint); insecure.IsTrue() && !isInternalHost(host) {
			out = append(out, newFinding(r.Metadata(), insecure.Loc,
				"Telemetry.InsecureConnection = true exports telemetry without TLS to %s", host))
		}
	}

	// CHIP ingress does not depend on Telemetry.Enabled: the durable emitter
	// (DurableEmitterEnabled, default true) sends to ChipIngressEndpoint with
	// ChipIngressInsecureConnection on its own (core/services/chainlink/
	// application.go, v2.69.0).
	chip := doc.Get("Telemetry.ChipIngressInsecureConnection")
	chipEndpoint, _ := doc.Get("Telemetry.ChipIngressEndpoint").String()
	if host := endpointHost(chipEndpoint); chip.IsTrue() && chipEndpoint != "" && !isInternalHost(host) {
		out = append(out, newFinding(r.Metadata(), chip.Loc,
			"Telemetry.ChipIngressInsecureConnection = true sends events without TLS to %s", host))
	}
	return out
}
