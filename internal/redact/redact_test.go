package redact

import (
	"strings"
	"testing"

	"github.com/brennocm/oraclint/internal/model"
)

func TestURL(t *testing.T) {
	tests := []struct{ in, want string }{
		{"postgres://user:hunter2@db.example.com:5432/cl?sslmode=disable", "postgres://user:****@db.example.com:5432/cl?sslmode=disable"},
		{"postgres://user@db/cl", "postgres://user@db/cl"},
		{"https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef", "https://mainnet.infura.io/v3/****"},
		{"wss://eth-mainnet.g.alchemy.com/v2/AbCdEfGhIjKlMnOpQrStUv1234567890", "wss://eth-mainnet.g.alchemy.com/v2/****"},
		{"https://rpc.example.com/?apikey=abc123&chain=1", "https://rpc.example.com/?apikey=****&chain=1"},
		{"https://rpc.example.com/?x_token=abc&key", "https://rpc.example.com/?x_token=****&key"},
		{"https://rpc.example.com/path/short#frag", "https://rpc.example.com/path/short#****"},
		{"https://rpc.example.com/ws/aaaaaaaaaaaaaaaaaaaaaaaaa", "https://rpc.example.com/ws/aaaaaaaaaaaaaaaaaaaaaaaaa"}, // no digit: not key-like
		{"postgres://u:p%40ss@db/x", "postgres://u:****@db/x"},
		{"not a url", "not a url"},
		{"postgres://u:pw@db:bad port/x", "postgres://u:****@db:bad port/x"}, // url.Parse fails: fallback
	}
	for _, tc := range tests {
		if got := URL(tc.in); got != tc.want {
			t.Errorf("URL(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}

func TestText(t *testing.T) {
	tests := []struct{ in, want string }{
		{"connects to postgres://u:secretpw@db/x with sslmode=disable", "connects to postgres://u:****@db/x with sslmode=disable"},
		{"password=hunter2 and api_key: abc", "password=**** and api_key: ****"},
		{"KeystorePassword = topsecret", "KeystorePassword = ****"},
		{"already password=****", "already password=****"},
		{"AllowSimplePasswords = true disables", "AllowSimplePasswords = true disables"},
		{"CL_DATABASE_ALLOW_SIMPLE_PASSWORDS=TRUE", "CL_DATABASE_ALLOW_SIMPLE_PASSWORDS=TRUE"},
		{"nothing to see at line 12", "nothing to see at line 12"},
	}
	for _, tc := range tests {
		if got := Text(tc.in); got != tc.want {
			t.Errorf("Text(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}

func TestRedactorApply(t *testing.T) {
	var r Redactor
	r.Add("abc")              // too short: ignored
	r.Add("  my-secret-1  ")  // trimmed
	r.Add("my-secret-1-long") // longer one containing the other
	got := r.Apply("a=abc b=my-secret-1 c=my-secret-1-long")
	if got != "a=abc b=**** c=****" {
		t.Errorf("Apply = %q", got)
	}
	var zero Redactor
	if zero.Apply("plain") != "plain" {
		t.Error("zero Redactor should only apply patterns")
	}
}

func target(t *testing.T, kind model.Kind, src string) *model.Target {
	t.Helper()
	tg := &model.Target{Kind: kind, Path: "f"}
	switch kind {
	case model.KindConfig, model.KindSecrets:
		root, err := model.ParseTOML("f.toml", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		tg.TOML = &model.TOMLDoc{Kind: kind, Root: root}
	case model.KindCompose, model.KindK8s:
		docs, err := model.ParseYAML("f.yaml", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		tg.YAML = docs
	case model.KindEnv:
		vars, err := model.ParseEnv(".env", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		tg.Env = vars
	}
	return tg
}

func TestCollect(t *testing.T) {
	tests := []struct {
		name    string
		kind    model.Kind
		src     string
		secrets []string // must be masked
		keep    []string // must survive
	}{
		{
			name:    "secrets file: every string",
			kind:    model.KindSecrets,
			src:     "[Password]\nKeystore = 'ks-value-1'\n[Database]\nURL = 'postgresql://u:db-pass-2@h/x'\nAllowSimplePasswords = true\n",
			secrets: []string{"ks-value-1", "db-pass-2"},
			keep:    []string{"true"},
		},
		{
			name:    "config: sensitive paths and URL parts",
			kind:    model.KindConfig,
			src:     "[Password]\nKeystore = 'misplaced-3'\n[Log]\nLevel = 'debug'\n[[EVM]]\nChainID = '1'\n[[EVM.Nodes]]\nName = 'primary'\nHTTPURL = 'https://x.example/v3/0123456789abcdef0123456789abcdef'\n[AuditLogger]\nHeaders = ['Authorization: bearer-tok-4']\n",
			secrets: []string{"misplaced-3", "0123456789abcdef0123456789abcdef", "Authorization: bearer-tok-4"},
			keep:    []string{"debug", "primary"},
		},
		{
			// Regression (found by FuzzNoSecretInFindings): numeric-looking
			// secrets used to be skipped.
			name:    "numeric secrets",
			kind:    model.KindSecrets,
			src:     "[Password]\nVRF = '00000000'\n",
			secrets: []string{"00000000"},
		},
		{
			name:    "env file",
			kind:    model.KindEnv,
			src:     "CL_PASSWORD_KEYSTORE=env-ks-5\nCL_DATABASE_URL=postgresql://u:env-db-6@h/x\nLOG_LEVEL=debug\nTOKEN_ENABLED=true\n",
			secrets: []string{"env-ks-5", "env-db-6"},
			keep:    []string{"debug", "true"},
		},
		{
			name: "compose map and list environment",
			kind: model.KindCompose,
			src: "services:\n  node:\n    environment:\n      CL_PASSWORD_KEYSTORE: compose-ks-7\n      LOG_LEVEL: info\n" +
				"  db:\n    environment:\n      - POSTGRES_PASSWORD=compose-pg-8\n      - TZ=UTC\n",
			secrets: []string{"compose-ks-7", "compose-pg-8"},
			keep:    []string{"info", "UTC"},
		},
		{
			name: "k8s env name/value pairs",
			kind: model.KindK8s,
			src: "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: node\n    env:\n    - name: CL_DATABASE_URL\n" +
				"      value: postgresql://u:k8s-db-9@h/x\n    - name: CL_PASSWORD_KEYSTORE\n      value: k8s-ks-10\n    - name: LOG\n      value: warn\n",
			secrets: []string{"k8s-db-9", "k8s-ks-10"},
			keep:    []string{"warn", "node"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var r Redactor
			Collect(&r, target(t, tc.kind, tc.src))
			for _, s := range tc.secrets {
				if out := r.Apply("value " + s + " end"); strings.Contains(out, s) {
					t.Errorf("secret %q not masked: %q", s, out)
				}
			}
			for _, k := range tc.keep {
				if out := r.Apply("value " + k + " end"); !strings.Contains(out, k) {
					t.Errorf("non-secret %q was masked: %q", k, out)
				}
			}
		})
	}
}

func TestCollectDeepYAMLIsBounded(t *testing.T) {
	src := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
	docs, err := model.ParseYAML("deep.yaml", []byte("a: "+src+"\n"))
	if err != nil {
		t.Skipf("parser rejected deep nesting: %v", err)
	}
	var r Redactor
	Collect(&r, &model.Target{Kind: model.KindCompose, YAML: docs}) // must not overflow the stack
}

// FuzzRedactorMasksRegisteredSecrets: whatever the surrounding text, a
// registered alphanumeric secret never survives Apply.
func FuzzRedactorMasksRegisteredSecrets(f *testing.F) {
	f.Add("hunter2hunter2", "password is %s, keep it safe")
	f.Add("0123456789abcdef", "https://rpc.example.com/v3/%s?key=%s")
	f.Fuzz(func(t *testing.T, secret, text string) {
		if len(secret) < minSecretLen || strings.Trim(secret, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != "" {
			return
		}
		var r Redactor
		r.Add(secret)
		in := strings.ReplaceAll(text, "%s", secret) + " " + secret
		if out := r.Apply(in); strings.Contains(out, secret) {
			t.Fatalf("secret %q survived: %q", secret, out)
		}
	})
}
