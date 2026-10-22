package rules

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/brennocm/oraclint/internal/loader"
	"github.com/brennocm/oraclint/internal/model"
)

func TestFSSecretsPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	tests := []struct {
		mode fs.FileMode
		want int
	}{
		{0o600, 0}, {0o400, 0}, {0o640, 1}, {0o644, 1}, {0o604, 1}, {0o660, 1},
	}
	for _, tc := range tests {
		t.Run(tc.mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secrets.toml")
			if err := os.WriteFile(path, []byte("[Password]\nKeystore = 'x'\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			res, err := loader.Load([]string{path}, loader.Options{})
			if err != nil || len(res.Targets) != 1 {
				t.Fatalf("load: %v %+v", err, res)
			}
			got := fsSecretsPermissions{}.Check(res.Targets[0])
			if len(got) != tc.want {
				t.Errorf("mode %v: %d findings, want %d", tc.mode, len(got), tc.want)
			}
		})
	}
	// Unknown mode (merged targets) is never reported.
	if got := (fsSecretsPermissions{}).Check(&model.Target{Kind: model.KindSecrets}); got != nil {
		t.Errorf("zero mode should be skipped, got %+v", got)
	}
}
