package rules

import "testing"

func TestWebLDAPNoTLS(t *testing.T) {
	runRuleCases(t, webLDAPNoTLS{}, []ruleCase{
		{"ldap without tls", cfg("[WebServer]\nAuthenticationMethod = 'ldap'\n[WebServer.LDAP]\nServerTLS = false\n"), []int{4}},
		{"ldap default tls", cfg("[WebServer]\nAuthenticationMethod = 'ldap'\n[WebServer.LDAP]\nBaseDN = 'dc=example,dc=com'\n"), nil},
		{"tls off but local auth", cfg("[WebServer.LDAP]\nServerTLS = false\n"), nil},
	})
}
