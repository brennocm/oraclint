package report

import (
	"encoding/json"
	"io"
	"io/fs"
	"strings"
	"unicode"

	"github.com/brennocm/oraclint/docs"
	"github.com/brennocm/oraclint/internal/rules"
)

// Minimal SARIF 2.1.0 types: only what oraclint emits. Written by hand rather
// than pulling a SARIF library, see ADR 0008. Field order follows the spec so
// the output is easy to read and diff.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	Help                 sarifHelp       `json:"help"`
	HelpURI              string          `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifRuleProps  `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	// GitHub code scanning reads this to rank alerts (0.0-10.0, as a string).
	SecuritySeverity string   `json:"security-severity"`
	Precision        string   `json:"precision"`
	Tags             []string `json:"tags"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

const sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

// sarifLevel maps severities onto SARIF's three result levels.
func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps severities onto GitHub's CVSS-like bands:
// critical > 9.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9.
func securitySeverity(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "9.5"
	case rules.SeverityHigh:
		return "8.0"
	case rules.SeverityMedium:
		return "5.5"
	case rules.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

func writeSARIF(w io.Writer, rep Report) error {
	catalog := append([]rules.Metadata{rules.ParseError}, rep.Rules...)
	index := make(map[string]int, len(catalog))
	driver := sarifDriver{
		Name:           "oraclint",
		Version:        rep.ToolVersion,
		InformationURI: InformationURI,
		Rules:          make([]sarifRule, 0, len(catalog)),
	}
	for i, m := range catalog {
		index[m.ID] = i
		driver.Rules = append(driver.Rules, sarifRuleFor(m))
	}

	results := make([]sarifResult, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		line := f.Location.Line
		if line < 1 {
			line = 1 // whole-file findings: SARIF regions need a line
		}
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: index[f.RuleID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: f.Message},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: relativePath(rep.BaseDir, f.Location.File), URIBaseID: "%SRCROOT%"},
				Region:           sarifRegion{StartLine: line, StartColumn: f.Location.Column},
			}}},
		})
	}

	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifRuleFor(m rules.Metadata) sarifRule {
	doc := ruleDoc(m.ID)
	if doc == "" {
		doc = "# " + m.Title + "\n\n" + m.Remediation
	}
	precision := "high"
	if m.Status == rules.Experimental {
		precision = "medium"
	}
	tags := []string{"security"}
	for _, k := range m.Targets {
		tags = append(tags, k.String())
	}
	tags = append(tags, m.CWE...)

	r := sarifRule{
		ID:                   m.ID,
		Name:                 ruleName(m.Title),
		ShortDescription:     sarifText{Text: m.Title},
		FullDescription:      sarifText{Text: m.Title + ". " + m.Remediation},
		Help:                 sarifHelp{Text: m.Remediation, Markdown: doc},
		DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(m.Severity)},
		Properties: sarifRuleProps{
			SecuritySeverity: securitySeverity(m.Severity),
			Precision:        precision,
			Tags:             tags,
		},
	}
	if strings.HasPrefix(m.ID, "NS-") {
		r.HelpURI = InformationURI + "/blob/main/docs/rules/" + m.ID + ".md"
	}
	return r
}

// ruleDoc returns the embedded Markdown documentation of a rule, or "".
func ruleDoc(id string) string {
	b, err := fs.ReadFile(docs.Rules, "rules/"+id+".md")
	if err != nil {
		return ""
	}
	return string(b)
}

// ruleName turns a title into the PascalCase identifier SARIF suggests,
// e.g. "RPC endpoint uses unencrypted transport" -> "RpcEndpointUsesUnencryptedTransport".
func ruleName(title string) string {
	var b strings.Builder
	notAlnum := func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }
	for _, word := range strings.FieldsFunc(title, notAlnum) {
		b.WriteString(strings.ToUpper(word[:1]) + strings.ToLower(word[1:]))
	}
	return b.String()
}
