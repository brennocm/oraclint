package rules

import "testing"

func TestWebSessionTimeout(t *testing.T) {
	runRuleCases(t, webSessionTimeout{}, []ruleCase{
		{"too long", cfg("[WebServer]\nSessionTimeout = '24h'\n"), []int{2}},
		{"exactly one hour", cfg("[WebServer]\nSessionTimeout = '1h'\n"), nil},
		{"just above", cfg("[WebServer]\nSessionTimeout = '1h0m1s'\n"), []int{2}},
		{"default", cfg(""), nil},
		{"invalid duration ignored", cfg("[WebServer]\nSessionTimeout = 'forever'\n"), nil},
		{"ldap timeout when ldap active", cfg("[WebServer]\nAuthenticationMethod = 'ldap'\n[WebServer.LDAP]\nSessionTimeout = '8h'\n"), []int{4}},
		{"ldap timeout ignored for local auth", cfg("[WebServer.LDAP]\nSessionTimeout = '8h'\n"), nil},
		{"oidc and local both long", cfg("[WebServer]\nAuthenticationMethod = 'oidc'\nSessionTimeout = '2h'\n[WebServer.OIDC]\nSessionTimeout = '12h'\n"), []int{3, 5}},
	})
}
