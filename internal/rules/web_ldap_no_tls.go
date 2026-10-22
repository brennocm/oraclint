package rules

import "github.com/brennocm/oraclint/internal/model"

// webLDAPNoTLS flags LDAP authentication without ldaps://. Every operator
// login, and the read-only bind account's password, would cross the network
// in cleartext.
type webLDAPNoTLS struct{}

func (webLDAPNoTLS) Metadata() Metadata {
	return Metadata{
		ID:          "NS-WEB-006",
		Title:       "LDAP authentication without TLS",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Remove WebServer.LDAP.ServerTLS = false (default true) and use an ldaps:// server address.",
		References:  []string{refConfig + "#webserverldap"},
		CWE:         []string{"CWE-319", "CWE-523"},
	}
}

func (r webLDAPNoTLS) Check(t *model.Target) []Finding {
	if method, _ := t.TOML.Get("WebServer.AuthenticationMethod").String(); method != "ldap" {
		return nil
	}
	f := t.TOML.Get("WebServer.LDAP.ServerTLS")
	if b, ok := f.Bool(); !ok || b {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), f.Loc,
		"WebServer.LDAP.ServerTLS = false sends operator credentials to the LDAP server in cleartext")}
}
