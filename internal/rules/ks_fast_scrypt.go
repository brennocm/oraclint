package rules

import "github.com/brennocm/oraclint/internal/model"

// ksFastScrypt flags InsecureFastScrypt = true. Unlike the [Insecure] flags,
// the node does not gate this setting by build mode, so a production node
// will happily run with it.
type ksFastScrypt struct{}

func (ksFastScrypt) Metadata() Metadata {
	return Metadata{
		ID:          "NS-KS-001",
		Title:       "Keystore encrypted with insecure fast scrypt parameters",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Remove InsecureFastScrypt (default false) and rotate keys created while it was enabled.",
		References:  []string{refConfig + "#insecurefastscrypt"},
		CWE:         []string{"CWE-916"},
	}
}

func (r ksFastScrypt) Check(t *model.Target) []Finding {
	f := t.TOML.Get("InsecureFastScrypt")
	if !f.IsTrue() {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), f.Loc,
		"InsecureFastScrypt = true makes every keystore use weak scrypt parameters, so a leaked database can be brute-forced offline")}
}
