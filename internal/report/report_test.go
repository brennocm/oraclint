package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/brennocm/oraclint/internal/model"
	"github.com/brennocm/oraclint/internal/rules"
)

var update = flag.Bool("update", false, "rewrite golden files")

var goldenDir = filepath.Join("..", "..", "testdata", "golden")

func allMetadata() []rules.Metadata {
	var out []rules.Metadata
	for _, r := range rules.All() {
		out = append(out, r.Metadata())
	}
	return out
}

func finding(id string, sev rules.Severity, file string, line, col int, msg string) rules.Finding {
	return rules.Finding{
		RuleID: id, Severity: sev, Title: "Title of " + id, Message: msg,
		Location:    model.Location{File: file, Line: line, Column: col},
		Remediation: "Fix " + id + ".",
	}
}

// sampleReport is the fixed input for the golden files.
func sampleReport() Report {
	return Report{
		ToolVersion:  "v0.0.0-test",
		Rules:        allMetadata(),
		FilesScanned: 3,
		Findings: []rules.Finding{
			finding("NS-KS-001", rules.SeverityHigh, "node/config.toml", 1, 1, "InsecureFastScrypt = true makes every keystore use weak scrypt parameters"),
			finding("NS-RPC-001", rules.SeverityHigh, "node/config.toml", 12, 1, `EVM chain "1" node "a": WSURL uses unencrypted ws:// to rpc.example.com`),
			finding("NS-DB-002", rules.SeverityHigh, "node/secrets.toml", 2, 1, "Database.URL connects to db.example.com with sslmode=disable"),
			finding("parse-error", rules.SeverityHigh, "ops/docker-compose.yml", 0, 0, "invalid YAML"),
			suppressed(finding("NS-WEB-001", rules.SeverityMedium, "node/config.toml", 20, 1, "HTTPS disabled"),
				rules.SuppressionInline, "TLS terminated at the load balancer", model.Location{File: "node/config.toml", Line: 19, Column: 1}),
			suppressed(finding("NS-LOG-001", rules.SeverityLow, "node/config.toml", 25, 1, "debug logs"),
				rules.SuppressionConfig, "staging node", model.Location{File: ".oraclint.yaml"}),
		},
	}
}

func suppressed(f rules.Finding, kind, reason string, src model.Location) rules.Finding {
	f.Suppression = &rules.Suppression{Kind: kind, Reason: reason, Source: src}
	return f
}

func TestGolden(t *testing.T) {
	for _, format := range []string{FormatText, FormatJSON, FormatSARIF} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Write(&buf, format, sampleReport(), Options{}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(goldenDir, "report."+format)
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden file (run make golden-update): %v", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("%s output differs from %s; run `make golden-update` and review the diff.\ngot:\n%s", format, path, buf.String())
			}
		})
	}
}

func TestEmptyReport(t *testing.T) {
	rep := Report{ToolVersion: "x", FilesScanned: 1}
	var text, js bytes.Buffer
	if err := Write(&text, FormatText, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "No issues found in 1 file.") {
		t.Errorf("text = %q", text.String())
	}
	if err := Write(&js, FormatJSON, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"findings": []`) {
		t.Errorf("empty findings must be [] not null: %s", js.String())
	}
}

func TestTextQuietAndSuppressed(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, sampleReport(), Options{Quiet: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "findings in") || strings.Contains(out, "NS-LOG-001") {
		t.Errorf("quiet output must have no summary and no suppressed findings:\n%s", out)
	}
	buf.Reset()
	rep := sampleReport()
	rep.Findings = rep.Findings[4:] // only the suppressed ones
	if err := Write(&buf, FormatText, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No issues found in 3 files (2 suppressed).") {
		t.Errorf("summary = %q", buf.String())
	}
}

func TestTextColor(t *testing.T) {
	var plain, colored bytes.Buffer
	if err := Write(&plain, FormatText, sampleReport(), Options{Color: false}); err != nil {
		t.Fatal(err)
	}
	if err := Write(&colored, FormatText, sampleReport(), Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "\x1b[") {
		t.Error("plain output contains ANSI escapes")
	}
	if !strings.Contains(colored.String(), ansiBold+ansiRed+"HIGH") {
		t.Error("colored output lacks the high severity color")
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "xml", Report{}, Options{}); err == nil {
		t.Error("expected error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestWriteErrorsPropagate(t *testing.T) {
	for _, format := range []string{FormatText, FormatJSON, FormatSARIF} {
		if err := Write(failingWriter{}, format, sampleReport(), Options{}); err == nil {
			t.Errorf("%s: expected write error", format)
		}
	}
}

func TestSARIFValidatesAgainstSchema(t *testing.T) {
	c := jsonschema.NewCompiler()
	schema, err := c.Compile(filepath.Join("..", "..", "testdata", "sarif", "sarif-schema-2.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, FormatSARIF, sampleReport(), Options{}); err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("SARIF output is not valid against the 2.1.0 schema: %v", err)
	}
}

func TestSARIFContent(t *testing.T) {
	rep := sampleReport()
	rep.BaseDir = filepath.FromSlash("/repo")
	rep.Findings = append(rep.Findings, finding("NS-KS-001", rules.SeverityHigh, "/repo/abs/config.toml", 3, 0, "m"))

	var buf bytes.Buffer
	if err := Write(&buf, FormatSARIF, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != len(rules.All())+2 {
		t.Errorf("driver rules = %d, want every rule plus the two pseudo rules", len(run.Tool.Driver.Rules))
	}
	var sup int
	for _, res := range run.Results {
		if len(res.Suppressions) == 1 {
			sup++
		}
	}
	if sup != 2 {
		t.Errorf("suppressed results = %d, want 2", sup)
	}
	for _, res := range run.Results {
		r := run.Tool.Driver.Rules[res.RuleIndex]
		if r.ID != res.RuleID {
			t.Errorf("ruleIndex %d points at %s, want %s", res.RuleIndex, r.ID, res.RuleID)
		}
		if res.Locations[0].PhysicalLocation.Region.StartLine < 1 {
			t.Error("startLine must be >= 1")
		}
	}
	last := run.Results[len(run.Results)-1]
	if uri := last.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "abs/config.toml" {
		t.Errorf("absolute path should be made relative to BaseDir, got %q", uri)
	}
	ks := run.Tool.Driver.Rules[run.Results[0].RuleIndex]
	if ks.Properties.SecuritySeverity != "8.0" || !strings.HasPrefix(ks.Help.Markdown, "# NS-KS-001") {
		t.Errorf("rule entry incomplete: %+v", ks)
	}
}

func TestArtifactFor(t *testing.T) {
	tests := []struct {
		base, file, uri, baseID string
	}{
		{"/repo", "node/config.toml", "node/config.toml", "%SRCROOT%"},
		{"/repo", "/repo/my dir/config.toml", "my%20dir/config.toml", "%SRCROOT%"},
		{"/repo", "/etc/chainlink/config.toml", "file:///etc/chainlink/config.toml", ""},
		{"/repo", "a:b/config.toml", "./a:b/config.toml", "%SRCROOT%"},
	}
	for _, tc := range tests {
		got := artifactFor(filepath.FromSlash(tc.base), tc.file)
		if got.URI != tc.uri || got.URIBaseID != tc.baseID {
			t.Errorf("artifactFor(%q) = %+v, want %q %q", tc.file, got, tc.uri, tc.baseID)
		}
	}
}

func TestHelpers(t *testing.T) {
	if got := ruleName("RPC endpoint uses un-encrypted transport"); got != "RpcEndpointUsesUnEncryptedTransport" {
		t.Errorf("ruleName = %q", got)
	}
	tests := []struct{ base, path, want string }{
		{"", "a/b.toml", "a/b.toml"},
		{"/repo", "a/b.toml", "a/b.toml"},
		{"/repo", "/repo/a/b.toml", "a/b.toml"},
		{"/repo", "/elsewhere/b.toml", "/elsewhere/b.toml"},
	}
	for _, tc := range tests {
		if got := relativePath(filepath.FromSlash(tc.base), tc.path); got != tc.want {
			t.Errorf("relativePath(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
	for s, want := range map[rules.Severity]string{
		rules.SeverityCritical: "error", rules.SeverityHigh: "error", rules.SeverityMedium: "warning",
		rules.SeverityLow: "note", rules.SeverityInfo: "note",
	} {
		if sarifLevel(s) != want {
			t.Errorf("sarifLevel(%s) = %s", s, sarifLevel(s))
		}
		if securitySeverity(s) == "" {
			t.Errorf("no security-severity for %s", s)
		}
	}
	c := countBySeverity([]rules.Finding{{Severity: rules.SeverityCritical}, {Severity: rules.SeverityLow}, {Severity: rules.SeverityInfo}, {Severity: rules.SeverityMedium}})
	if c.Total() != 4 || c.Critical != 1 || c.Info != 1 {
		t.Errorf("counts = %+v", c)
	}
}
