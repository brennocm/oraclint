//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The report must be readable by other users: in the GitHub Action the scan
// runs as root and the upload step as the runner user.
func TestWriteFileModeIsReadableByOthers(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	path := filepath.Join(t.TempDir(), "report.sarif")
	if err := writeFile(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("report mode = %04o, want 0644", got)
	}
}
