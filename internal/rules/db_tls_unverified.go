package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// dbTLSUnverified flags remote Postgres connections whose TLS does not verify
// the server: no sslmode (the Go driver then uses "prefer", which falls back
// to plaintext), "prefer", or "require" without a root certificate. An active
// attacker can impersonate the database. Experimental: plenty of managed
// databases are reached this way inside trusted networks.
type dbTLSUnverified struct{}

func (dbTLSUnverified) Metadata() Metadata {
	return Metadata{
		ID:          "NS-DB-003",
		Title:       "Postgres TLS does not verify the server",
		Severity:    SeverityLow,
		Targets:     []model.Kind{model.KindSecrets},
		Status:      Experimental,
		Remediation: "Use sslmode=verify-full with sslrootcert pointing to the database CA.",
		References:  []string{refSecrets + "#database", "https://www.postgresql.org/docs/current/libpq-ssl.html"},
		CWE:         []string{"CWE-295"},
	}
}

func (r dbTLSUnverified) Check(t *model.Target) []Finding {
	var out []Finding
	for _, key := range []string{"Database.URL", "Database.BackupURL"} {
		v := t.TOML.Root.Get(key)
		if v == nil {
			continue
		}
		raw, _ := v.Scalar.(string)
		host, params, ok := postgresTarget(raw)
		if !ok || isInternalHost(host) {
			continue
		}
		mode := strings.ToLower(params.Get("sslmode"))
		switch {
		case mode == "" || mode == "prefer":
			out = append(out, newFinding(r.Metadata(), v.Loc,
				"%s to %s does not require TLS (sslmode %s), so a network attacker can downgrade the connection", key, host, displayMode(mode)))
		case mode == "require" && params.Get("sslrootcert") == "":
			out = append(out, newFinding(r.Metadata(), v.Loc,
				"%s to %s uses sslmode=require, which encrypts but does not verify the server certificate", key, host))
		}
	}
	return out
}

func displayMode(mode string) string {
	if mode == "" {
		return "not set, driver default prefer"
	}
	return "=" + mode
}
