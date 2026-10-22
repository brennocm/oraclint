package rules

import (
	"net/url"
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// dbTLSDisabled flags a Postgres connection to a non-internal host with TLS
// turned off. The node database holds encrypted keys, job specs and
// transaction state; the connection also carries the database password.
type dbTLSDisabled struct{}

func (dbTLSDisabled) Metadata() Metadata {
	return Metadata{
		ID:          "NS-DB-002",
		Title:       "Postgres connection to remote host without TLS",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindSecrets},
		Status:      Stable,
		Remediation: "Use sslmode=verify-full (or at least sslmode=require) for databases reached over a network.",
		References:  []string{refSecrets + "#database", refRunningNode, "https://www.postgresql.org/docs/current/libpq-ssl.html"},
		CWE:         []string{"CWE-319"},
	}
}

func (r dbTLSDisabled) Check(t *model.Target) []Finding {
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
		sslmode := strings.ToLower(params.Get("sslmode"))
		if sslmode == "disable" || sslmode == "allow" {
			out = append(out, newFinding(r.Metadata(), v.Loc,
				"%s connects to %s with sslmode=%s, sending credentials and node data in cleartext", key, host, sslmode))
		}
	}
	return out
}

// postgresTarget extracts the target host and the query parameters from a
// postgres:// URL. A host given as a query parameter starting with "/" is a
// Unix socket and reported as "" (internal). ok is false for anything that is
// not a parsable postgres URL.
func postgresTarget(raw string) (host string, params url.Values, ok bool) {
	// url.Parse directly, not parseURL: "postgresql://u:p@/db?host=..." has
	// an empty authority host and is still valid.
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", nil, false
	}
	if s := strings.ToLower(u.Scheme); s != "postgres" && s != "postgresql" {
		return "", nil, false
	}
	q := u.Query()
	host = u.Hostname()
	if qh := q.Get("host"); qh != "" {
		host = qh
		if strings.HasPrefix(qh, "/") {
			host = ""
		}
	}
	return host, q, true
}
