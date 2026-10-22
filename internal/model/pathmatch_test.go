package model

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchPath(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		pattern, file string
		want          bool
	}{
		{"deploy/staging/**", "deploy/staging/config.toml", true},
		{"deploy/staging/**", "deploy/staging/k8s/node.yaml", true},
		{"deploy/staging/**", "deploy/staging", true},
		{"deploy/staging/**", "deploy/staging-old/config.toml", false},
		{"deploy/*/config.toml", "deploy/prod/config.toml", true},
		{"deploy/*/config.toml", "deploy/prod/x/config.toml", false},
		{"./config.toml", "config.toml", true},
		{"config.toml", "other/config.toml", false},
		{"**", "anything/at/all", false}, // "**" alone is a single-segment glob
		{"testdata/**", filepath.Join(cwd, "testdata", "x.toml"), true},
		{"testdata/**", "/elsewhere/testdata/x.toml", false},
	}
	for _, tc := range tests {
		if got := MatchPath(tc.pattern, tc.file); got != tc.want {
			t.Errorf("MatchPath(%q, %q) = %v, want %v", tc.pattern, tc.file, got, tc.want)
		}
	}
	for p, want := range map[string]bool{"a/**": true, "*.toml": true, "[": false, "  ": false} {
		if ValidPattern(p) != want {
			t.Errorf("ValidPattern(%q) != %v", p, want)
		}
	}
}
