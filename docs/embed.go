// Package docs embeds the per-rule documentation into the oraclint binary,
// so `oraclint rules explain <ID>` works offline. It lives next to the
// Markdown files because go:embed cannot reference parent directories.
package docs

import "embed"

// Rules holds docs/rules/<RULE-ID>.md for every rule.
//
//go:embed rules/*.md
var Rules embed.FS
