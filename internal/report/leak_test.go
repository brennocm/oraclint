package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brennocm/oraclint/internal/engine"
	"github.com/brennocm/oraclint/internal/loader"
	"github.com/brennocm/oraclint/internal/model"
	"github.com/brennocm/oraclint/internal/rules"
)

// leakyRule simulates a buggy rule that copies a raw value into its message.
// The engine must still mask it.
type leakyRule struct{ inner rules.Rule }

func (r leakyRule) Metadata() rules.Metadata { return r.inner.Metadata() }

func (r leakyRule) Check(t *model.Target) []rules.Finding {
	findings := r.inner.Check(t)
	for i := range findings {
		findings[i].Message += " | raw: " + dumpStrings(t)
	}
	return findings
}

// dumpStrings returns every raw string value of a target, joined.
func dumpStrings(t *model.Target) string {
	var parts []string
	var walk func(v *model.Value)
	walk = func(v *model.Value) {
		if v == nil {
			return
		}
		for _, k := range v.SortedKeys() {
			walk(v.Table[k])
		}
		for _, item := range v.Array {
			walk(item)
		}
		if s, ok := v.Scalar.(string); ok {
			parts = append(parts, s)
		}
	}
	if t.TOML != nil {
		walk(t.TOML.Root)
	}
	for _, e := range t.Env {
		parts = append(parts, e.Name+"="+e.Value)
	}
	return strings.Join(parts, " ")
}

// FuzzNoSecretInOutput writes a deployment containing random secrets, runs
// the full loader + engine pipeline with every rule (plus a deliberately leaky
// copy of each rule) and renders every output format. No secret may appear in
// any of them. This is the executable form of the redaction invariant in
// docs/THREAT_MODEL.md.
func FuzzNoSecretInOutput(f *testing.F) {
	f.Add("Keystore0Password1x", "dbPassword2345", "0123456789abcdef0123456789abcdef", "vrfPass987654")
	f.Fuzz(func(t *testing.T, keystore, dbPass, rpcKey, vrf string) {
		for _, s := range []string{keystore, dbPass, rpcKey, vrf} {
			if !isFuzzSecret(s) {
				return
			}
		}
		// Keys in URL paths are recognized heuristically (>= 20 characters with
		// a digit, like Infura/Alchemy/QuickNode keys); see redact.URL.
		if len(rpcKey) < 20 || !strings.ContainsAny(rpcKey, "0123456789") {
			return
		}
		dir := t.TempDir()
		write(t, dir, "secrets.toml", fmt.Sprintf(
			"[Password]\nKeystore = '%s'\nVRF = '%s'\n[Database]\nURL = 'postgresql://cl:%s@db.example.com/cl?sslmode=disable'\n",
			keystore, vrf, dbPass))
		write(t, dir, "config.toml", fmt.Sprintf(
			"[Password]\nKeystore = '%s'\n[[EVM]]\nChainID = '1'\n[[EVM.Nodes]]\nName = 'n'\nHTTPURL = 'http://rpc.example.com/v3/%s'\n",
			keystore, rpcKey))
		write(t, dir, ".env", fmt.Sprintf("CL_PASSWORD_KEYSTORE=%s\nCL_DATABASE_URL=postgresql://cl:%s@db.example.com/cl\n", keystore, dbPass))

		res, err := loader.Load([]string{dir}, loader.Options{})
		if err != nil {
			t.Fatal(err)
		}
		all := rules.All()
		for _, r := range rules.All() {
			all = append(all, leakyRule{inner: r})
		}
		findings := engine.Run(res.Targets, res.Problems, all, engine.Options{Experimental: true})
		if len(findings) == 0 {
			t.Fatal("expected findings from the vulnerable deployment")
		}
		rep := Report{ToolVersion: "fuzz", Rules: allMetadata(), Findings: findings, FilesScanned: len(res.Targets)}
		for _, format := range []string{FormatText, FormatJSON, FormatSARIF} {
			var buf bytes.Buffer
			if err := Write(&buf, format, rep, Options{Color: true}); err != nil {
				t.Fatal(err)
			}
			for _, s := range []string{keystore, dbPass, rpcKey, vrf} {
				if strings.Contains(buf.String(), s) {
					t.Fatalf("secret %q leaked in %s output", s, format)
				}
			}
		}
	})
}

// isFuzzSecret keeps generated secrets realistic: long enough and made of
// characters that need no escaping in TOML, URLs or dotenv files.
func isFuzzSecret(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return strings.Trim(s, alnum) == "" // empty only if every character is alphanumeric
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
