package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
	"github.com/brennocm/oraclint/internal/redact"
)

// rpcCredentialInURL flags RPC URLs that embed a credential: userinfo, a
// key-like path segment (Infura /v3/<key>, Alchemy /v2/<key>, QuickNode
// /<token>/) or a sensitive query parameter. The node has no secrets field for
// RPC URLs, so these keys live in config files that tend to be committed.
type rpcCredentialInURL struct{}

func (rpcCredentialInURL) Metadata() Metadata {
	return Metadata{
		ID:          "NS-RPC-002",
		Title:       "Credential embedded in RPC URL",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Keep RPC URLs in a config file that is not committed or inject them via CL_CONFIG from a secret store; restrict the key at the provider (allowed IPs/origins).",
		References:  []string{refConfig + "#evmnodes"},
		CWE:         []string{"CWE-798", "CWE-312"},
	}
}

func (r rpcCredentialInURL) Check(t *model.Target) []Finding {
	var out []Finding
	// Disabled chains are checked too: the key is exposed in the file either way.
	for _, chain := range t.TOML.Root.Get("EVM").Items() {
		chainID := scalarText(chain.Get("ChainID"))
		for _, node := range chain.Get("Nodes").Items() {
			for _, key := range rpcURLKeys {
				v := node.Get(key)
				if v == nil {
					continue
				}
				raw, _ := v.Scalar.(string)
				where := credentialPlace(raw)
				if where == "" {
					continue
				}
				out = append(out, newFinding(r.Metadata(), v.Loc,
					"EVM chain %s node %s: %s embeds what looks like a credential (%s)",
					chainID, scalarText(node.Get("Name")), key, where))
			}
		}
	}
	return out
}

// credentialPlace says where a URL carries a credential, or "" if it does
// not appear to.
func credentialPlace(raw string) string {
	u, ok := parseURL(raw)
	if !ok {
		return ""
	}
	if u.User != nil {
		return "user info"
	}
	// Iterate in query order, not map order, so the message is deterministic.
	for _, pair := range strings.Split(u.RawQuery, "&") {
		name, _, _ := strings.Cut(pair, "=")
		if redact.SensitiveParam(name) {
			return "query parameter " + name
		}
	}
	for _, seg := range splitPath(u.Path) {
		if redact.KeyLikeSegment(seg) {
			return "URL path"
		}
	}
	return ""
}
