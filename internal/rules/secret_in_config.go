package rules

import "github.com/brennocm/oraclint/internal/model"

// secretInConfig flags secret settings written into a config file. The node
// decodes config.toml strictly and refuses to start with them, so this is an
// early warning; the real damage is that config files are usually committed
// to version control and shared, while secrets.toml is not.
type secretInConfig struct{}

// Keys that only exist in the secrets schema and hold secret values
// (docs/SECRETS.md, v2.69.0).
var secretOnlyPaths = []string{
	"Database.URL",
	"Database.BackupURL",
	"Password.Keystore",
	"Password.VRF",
	"WebServer.LDAP.ReadOnlyUserPass",
	"WebServer.OIDC.clientSecret",
	"WebServer.OIDC.ClientSecret",
	"Prometheus.AuthToken",
	"Pyroscope.AuthToken",
	"Mercury.Credentials",
	"Threshold.ThresholdKeyShare",
	"CRE.Streams.ApiKey",
	"CRE.Streams.ApiSecret",
	"CRE.LocalSecretOverrides",
	"P2PKey",
	"DKGRecipientKey",
}

func (secretInConfig) Metadata() Metadata {
	return Metadata{
		ID:          "NS-SEC-001",
		Title:       "Secret setting in config file",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Move the setting to secrets.toml (or its CL_* environment variable) and rotate the exposed secret.",
		References:  []string{refSecrets, refConfig},
		CWE:         []string{"CWE-260", "CWE-312"},
	}
}

func (r secretInConfig) Check(t *model.Target) []Finding {
	var out []Finding
	for _, path := range secretOnlyPaths {
		v := t.TOML.Root.Get(path)
		if v == nil {
			continue
		}
		out = append(out, newFinding(r.Metadata(), v.Loc,
			"%s belongs in secrets.toml; config files are often committed, and the node refuses to start with it here", path))
	}
	return out
}
