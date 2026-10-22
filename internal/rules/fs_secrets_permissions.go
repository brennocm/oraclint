package rules

import (
	"runtime"

	"github.com/brennocm/oraclint/internal/model"
)

// fsSecretsPermissions flags a secrets file readable or writable by group or
// others. Any local user or compromised service on the host could then read
// the database password and keystore password.
type fsSecretsPermissions struct{}

func (fsSecretsPermissions) Metadata() Metadata {
	return Metadata{
		ID:          "NS-FS-001",
		Title:       "Secrets file accessible by group or others",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindSecrets},
		Status:      Stable,
		Remediation: "chmod 600 the secrets file and make it owned by the user that runs the node.",
		References:  []string{refSecrets},
		CWE:         []string{"CWE-732"},
	}
}

func (r fsSecretsPermissions) Check(t *model.Target) []Finding {
	// Windows has no POSIX permission bits (Go reports 0666/0444), and a
	// zero mode means unknown (e.g. merged targets).
	if runtime.GOOS == "windows" || t.Mode == 0 {
		return nil
	}
	if t.Mode&0o077 == 0 {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), model.Location{File: t.Path},
		"secrets file has mode %04o; group or other users can access it", uint32(t.Mode.Perm()))}
}
