package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	info := BuildInfo{Version: "v1.2.3", Commit: "abc123", Date: "2026-01-01"}
	cmd := NewRootCommand(info)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version returned error: %v", err)
	}
	for _, want := range []string{"oraclint v1.2.3", "commit: abc123", "built: 2026-01-01"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output %q does not contain %q", out.String(), want)
		}
	}
}
