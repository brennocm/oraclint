package loader

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/brennocm/oraclint/internal/model"
)

// writeTree creates files (path -> content) under dir.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// summary maps display path (relative to dir) to kind name.
func summary(t *testing.T, dir string, res *Result) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, tg := range res.Targets {
		rel, err := filepath.Rel(dir, filepath.FromSlash(tg.Path))
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.ToSlash(rel)] = tg.Kind.String()
	}
	return out
}

func TestLoadDiscovery(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"node/config.toml":          "[Log]\nLevel = 'debug'\n",
		"node/secrets.toml":         "[Password]\nKeystore = 'x'\n",
		"node/overrides.toml":       "[[EVM]]\nChainID = '1'\n",
		"node/db.toml":              "[Database]\nURL = 'postgresql://localhost/db'\n",
		"Cargo.toml":                "[package]\nname = 'x'\n",
		"hugo/config.toml":          "baseURL = 'https://example.org'\n",
		"docker-compose.yml":        "services:\n  node:\n    image: smartcontract/chainlink:2.69.0\n",
		"compose.prod.yaml":         "services: {}\n",
		"k8s/deploy.yaml":           "apiVersion: apps/v1\nkind: Deployment\n",
		"k8s/values.yaml":           "replicas: 2\n",
		"chart/templates/svc.yaml":  "apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Release.Name }}\n",
		".env":                      "CL_PASSWORD_KEYSTORE=x\n",
		".env.production":           "A=1\n",
		"node.env":                  "A=1\n",
		".env.example":              "CL_PASSWORD_KEYSTORE=changeme\n",
		"node_modules/x/.env":       "A=1\n",
		".git/config.toml":          "[Log]\nLevel = 'debug'\n",
		"README.md":                 "# readme\n",
		"broken/docker-compose.yml": "services: [unclosed\n",
	})

	res, err := Load([]string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := summary(t, dir, res)
	want := map[string]string{
		"node/config.toml":    "config",
		"node/secrets.toml":   "secrets",
		"node/overrides.toml": "config",
		"node/db.toml":        "secrets",
		"docker-compose.yml":  "compose",
		"compose.prod.yaml":   "compose",
		"k8s/deploy.yaml":     "k8s",
		".env":                "env",
		".env.production":     "env",
		"node.env":            "env",
	}
	if len(got) != len(want) {
		t.Errorf("targets = %v\nwant %v", got, want)
	}
	for path, kind := range want {
		if got[path] != kind {
			t.Errorf("%s: kind = %q, want %q", path, got[path], kind)
		}
	}

	// Only the file with a strong name signal yields a problem; the Helm
	// template (weak signal) is silently skipped.
	if len(res.Problems) != 1 || !strings.HasSuffix(res.Problems[0].Loc.File, "broken/docker-compose.yml") {
		t.Errorf("problems = %+v, want one for broken/docker-compose.yml", res.Problems)
	}

	// Output order is deterministic.
	for i := 1; i < len(res.Targets); i++ {
		if res.Targets[i-1].Path > res.Targets[i].Path {
			t.Errorf("targets not sorted: %s > %s", res.Targets[i-1].Path, res.Targets[i].Path)
		}
	}
}

func TestLoadSizeLimit(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"config.toml":     "Log.Level = '" + strings.Repeat("a", 200) + "'\n",
		"big.yaml":        "a: " + strings.Repeat("b", 200) + "\n",
		"exact/.env":      strings.Repeat("A", 98) + "=\n", // exactly 100 bytes
		"secrets.toml":    "",
		"other/node.toml": "",
	})
	res, err := Load([]string{dir}, Options{MaxFileSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 1 || !strings.Contains(res.Problems[0].Msg, "larger than 100 bytes") {
		t.Fatalf("problems = %+v, want one size problem for config.toml", res.Problems)
	}
	if !strings.HasSuffix(res.Problems[0].Loc.File, "config.toml") {
		t.Errorf("size problem reported for %s", res.Problems[0].Loc.File)
	}
	got := summary(t, dir, res)
	if got["exact/.env"] != "env" {
		t.Errorf("file exactly at the limit should be scanned: %v", got)
	}
}

func TestLoadSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"secrets.toml": "[Password]\nKeystore = 'outside'\n"})

	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"real/config.toml": "[Log]\nLevel = 'info'\n"})
	mustSymlink(t, filepath.Join(outside, "secrets.toml"), filepath.Join(dir, "secrets.toml"))
	mustSymlink(t, filepath.Join(dir, "real", "config.toml"), filepath.Join(dir, "config.toml"))
	mustSymlink(t, filepath.Join(dir, "missing.toml"), filepath.Join(dir, "broken.toml"))

	res, err := Load([]string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := summary(t, dir, res)
	if _, ok := got["secrets.toml"]; ok {
		t.Error("symlink escaping the scan root must not be followed")
	}
	if got["config.toml"] != "config" {
		t.Errorf("symlink inside the root should be scanned: %v", got)
	}
}

func mustSymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Fatal(err)
	}
}

func TestLoadForcedAndMerged(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"a.toml":       "[WebServer]\nAllowOrigins = 'https://ui.example'\nSecureCookies = false\n",
		"b.toml":       "[WebServer]\nAllowOrigins = '*'\n",
		"weird-name":   "[Password]\nKeystore = 'x'\n",
		"stack.yml":    "services: {}\n",
		"manifest.txt": "apiVersion: v1\nkind: Pod\n",
		"vars":         "A=1\n",
	})
	p := func(name string) string { return filepath.Join(dir, name) }

	res, err := Load([]string{p("a.toml")}, Options{
		Config:  []string{p("a.toml"), p("b.toml")},
		Secrets: []string{p("weird-name")},
		Compose: []string{p("stack.yml")},
		K8s:     []string{p("manifest.txt")},
		Env:     []string{p("vars")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Targets) != 5 {
		t.Fatalf("targets = %d, want 5 (a.toml must not be loaded twice)", len(res.Targets))
	}
	var cfg *model.Target
	for _, tg := range res.Targets {
		if tg.Kind == model.KindConfig {
			cfg = tg
		}
	}
	if cfg == nil || len(cfg.Files) != 2 {
		t.Fatalf("expected one merged config target from two files, got %+v", cfg)
	}
	origins := cfg.TOML.Get("WebServer.AllowOrigins")
	if s, _ := origins.String(); s != "*" || !strings.HasSuffix(origins.Loc.File, "b.toml") {
		t.Errorf("AllowOrigins = %q from %s, want '*' from b.toml", s, origins.Loc.File)
	}
	if cookies := cfg.TOML.Get("WebServer.SecureCookies"); cookies.IsTrue() || !strings.HasSuffix(cookies.Loc.File, "a.toml") {
		t.Errorf("SecureCookies should come from a.toml")
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name  string
		paths []string
		opts  Options
	}{
		{"missing path", []string{filepath.Join(dir, "nope")}, Options{}},
		{"missing forced config", nil, Options{Config: []string{filepath.Join(dir, "nope.toml")}}},
		{"forced directory", nil, Options{Secrets: []string{dir}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(tc.paths, tc.opts); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestLoadParseErrorInForcedFile(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"c.toml": "[Log\n", "s.toml": "x = \n"})
	res, err := Load(nil, Options{
		Config:  []string{filepath.Join(dir, "c.toml")},
		Secrets: []string{filepath.Join(dir, "s.toml")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Targets) != 0 || len(res.Problems) != 2 {
		t.Errorf("targets=%d problems=%d, want 0 and 2", len(res.Targets), len(res.Problems))
	}
	for _, p := range res.Problems {
		if p.Loc.Line == 0 {
			t.Errorf("parse problem without line: %+v", p)
		}
	}
}

func TestClassifyByName(t *testing.T) {
	tests := []struct {
		name   string
		format format
		kind   model.Kind
		strong bool
	}{
		{"docker-compose.yml", formatYAML, model.KindCompose, true},
		{"Docker-Compose.override.YAML", formatYAML, model.KindCompose, true},
		{"compose.yaml", formatYAML, model.KindCompose, true},
		{"compose.txt", formatNone, 0, false},
		{".env", formatEnv, model.KindEnv, true},
		{".env.local", formatEnv, model.KindEnv, true},
		{".env.sample", formatNone, 0, false},
		{"prod.env", formatEnv, model.KindEnv, true},
		{"config.toml", formatTOML, 0, true},
		{"node-secrets.toml", formatTOML, 0, true},
		{"chain.toml", formatTOML, 0, false},
		{"deploy.yml", formatYAML, 0, false},
		{"main.go", formatNone, 0, false},
	}
	for _, tc := range tests {
		got := classifyByName(tc.name)
		if got.format != tc.format || got.kind != tc.kind || got.strong != tc.strong {
			t.Errorf("classifyByName(%q) = %+v, want {%v %v %v}", tc.name, got, tc.format, tc.kind, tc.strong)
		}
	}
}
