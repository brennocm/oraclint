package loader

import (
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/brennocm/oraclint/internal/model"
)

// format is the syntax of a file, which decides the parser.
type format int

const (
	formatNone format = iota
	formatTOML
	formatYAML
	formatEnv
)

// class is what the loader knows about a file before parsing it.
type class struct {
	format format
	// kind is 0 when it must be decided from the content.
	kind model.Kind
	// strong is true when the file name (or a flag) clearly says the file is
	// relevant; parse errors are then reported instead of ignored.
	strong bool
}

func forcedClass(k model.Kind) class {
	switch k {
	case model.KindConfig, model.KindSecrets:
		return class{format: formatTOML, kind: k, strong: true}
	case model.KindCompose, model.KindK8s:
		return class{format: formatYAML, kind: k, strong: true}
	case model.KindEnv:
		return class{format: formatEnv, kind: k, strong: true}
	default:
		return class{}
	}
}

// classifyByName looks only at the file name.
func classifyByName(name string) class {
	lower := strings.ToLower(name)
	ext := filepath.Ext(lower)

	switch {
	case isComposeName(lower):
		return class{format: formatYAML, kind: model.KindCompose, strong: true}
	case isEnvName(lower):
		return class{format: formatEnv, kind: model.KindEnv, strong: true}
	case ext == ".toml":
		// config.toml is a common name in other ecosystems too (Cargo, Hugo),
		// so the content still decides; but parse errors are worth reporting.
		strong := lower == "config.toml" || strings.Contains(lower, "secret")
		return class{format: formatTOML, strong: strong}
	case ext == ".yaml" || ext == ".yml":
		return class{format: formatYAML}
	default:
		return class{}
	}
}

func isComposeName(lower string) bool {
	ext := filepath.Ext(lower)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	return strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose")
}

// envTemplateSuffixes mark dotenv files meant to be committed with
// placeholder values. They are not scanned by default to avoid noise; they
// can still be scanned with --env.
var envTemplateSuffixes = []string{".example", ".sample", ".template", ".dist", ".tmpl"}

func isEnvName(lower string) bool {
	if lower != ".env" && !strings.HasPrefix(lower, ".env.") && !strings.HasSuffix(lower, ".env") {
		return false
	}
	for _, suffix := range envTemplateSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	return true
}

// Top-level tables that exist only in the node config schema (v2.69.0).
// Tables shared with the secrets schema (Database, WebServer, Mercury,
// Pyroscope, EVM, Solana, CRE) are not used as signals.
var configOnlyKeys = []string{
	"InsecureFastScrypt", "InsecurePPROFHeap", "RootDir", "ShutdownGracePeriod",
	"Feature", "TelemetryIngress", "AuditLogger", "Log", "JobDistributor",
	"JobPipeline", "FluxMonitor", "OCR2", "OCR", "P2P", "Workflows", "AutoPprof",
	"Sentry", "Insecure", "Tracing", "Telemetry", "Metering", "Billing",
	"BridgeStatusReporter", "JobSpecReporter", "Sharding", "LOOPP", "Starknet",
	"Capabilities",
}

// Top-level tables that exist only in the secrets schema.
var secretsOnlyKeys = []string{"Password", "Prometheus", "Threshold", "P2PKey", "DKGRecipientKey", "CCV"}

// classifyTOML decides whether a parsed TOML file is a node config, a node
// secrets file, or neither (0).
func classifyTOML(name string, root *model.Value) model.Kind {
	if strings.Contains(strings.ToLower(name), "secret") {
		return model.KindSecrets
	}
	for _, k := range configOnlyKeys {
		if root.Get(k) != nil {
			return model.KindConfig
		}
	}
	for _, chain := range root.Get("EVM").Items() {
		if chain.Get("ChainID") != nil {
			return model.KindConfig
		}
	}
	for _, k := range secretsOnlyKeys {
		if root.Get(k) != nil {
			return model.KindSecrets
		}
	}
	if root.Get("Database.URL") != nil || root.Get("Database.BackupURL") != nil {
		return model.KindSecrets
	}
	return 0
}

// looksLikeK8s reports whether any document has the apiVersion and kind
// fields every Kubernetes object carries.
func looksLikeK8s(docs []*yaml.Node) bool {
	for _, d := range docs {
		_, hasAPI := model.ScalarString(model.MapValue(d, "apiVersion"))
		_, hasKind := model.ScalarString(model.MapValue(d, "kind"))
		if hasAPI && hasKind {
			return true
		}
	}
	return false
}
