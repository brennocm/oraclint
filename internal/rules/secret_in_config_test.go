package rules

import (
	"strings"
	"testing"
)

func TestSecretInConfig(t *testing.T) {
	runRuleCases(t, secretInConfig{}, []ruleCase{
		{"keystore password", cfg("[Log]\nLevel = 'info'\n[Password]\nKeystore = 'abc'\n"), []int{4}},
		{"database url and backup", cfg("[Database]\nMaxIdleConns = 10\nURL = 'postgresql://u:p@h/db'\nBackupURL = 'postgresql://u:p@r/db'\n"), []int{3, 4}},
		{"whole credential table", cfg("[Mercury.Credentials.main]\nUsername = 'u'\nPassword = 'p'\n"), []int{1}},
		{"normal config", cfg("[Database]\nMaxIdleConns = 10\n[WebServer.LDAP]\nServerTLS = true\n"), nil},
	})

	f := secretInConfig{}.Check(configTarget(t, "[Password]\nKeystore = 'super-secret-value'\n"))
	if strings.Contains(f[0].Message, "super-secret-value") {
		t.Errorf("message leaks the secret: %q", f[0].Message)
	}
}
