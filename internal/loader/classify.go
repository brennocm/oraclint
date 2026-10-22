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
	// explicit is true for files named on the command line: if they turn out
	// not to be a node file, that is reported instead of silently skipped.
	explicit bool
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

// Top-level tables of the node config schema (v2.69.0), including those it
// shares with the secrets schema.
var configTopLevel = []string{
	"InsecureFastScrypt", "InsecurePPROFHeap", "RootDir", "ShutdownGracePeriod",
	"Feature", "Database", "TelemetryIngress", "AuditLogger", "Log", "WebServer",
	"JobDistributor", "JobPipeline", "FluxMonitor", "OCR2", "OCR", "P2P",
	"Workflows", "AutoPprof", "Pyroscope", "Sentry", "Insecure", "Tracing",
	"Mercury", "Telemetry", "Metering", "Billing", "BridgeStatusReporter",
	"JobSpecReporter", "CRE", "Sharding", "LOOPP", "EVM", "Solana", "Starknet",
	"Capabilities", "Aptos", "Tron", "Cosmos", "Sui", "Ton", "Stellar",
}

// secretsPaths are the key paths of the secrets schema (docs/SECRETS.md and
// the Secrets struct in core/config/toml/types.go, v2.69.0). A path matches
// itself and everything below it.
var secretsPaths = []string{
	"Database.URL", "Database.BackupURL", "Database.AllowSimplePasswords",
	"Password", "Prometheus", "Threshold", "P2PKey", "DKGRecipientKey", "CCV",
	"WebServer.OIDC.clientSecret", "WebServer.OIDC.ClientSecret",
	"WebServer.LDAP.ServerAddress", "WebServer.LDAP.ReadOnlyUserLogin", "WebServer.LDAP.ReadOnlyUserPass",
	"Pyroscope.AuthToken", "Mercury.Credentials",
	"CRE.Streams.ApiKey", "CRE.Streams.ApiSecret", "CRE.LocalSecretOverrides",
	"EVM.Keys", "Solana.Keys", "Aptos.Keys", "Stellar.Keys",
}

// classifyTOML decides whether a parsed TOML file is a node config, a node
// secrets file, or neither (0):
//
//  1. a file name containing "secret" is a secrets file;
//  2. a file whose keys all belong to the secrets schema is a secrets file;
//  3. a file with any top-level table of the config schema is a config file
//     (this includes config files with misplaced secrets, see NS-SEC-001);
//  4. anything else (Cargo.toml, pyproject.toml, ...) is not a node file.
func classifyTOML(name string, root *model.Value) model.Kind {
	if strings.Contains(strings.ToLower(name), "secret") {
		return model.KindSecrets
	}
	leaves := leafPaths(root, "")
	if len(leaves) == 0 {
		return 0
	}
	allSecrets := true
	for _, p := range leaves {
		if !underAny(p, secretsPaths) {
			allSecrets = false
			break
		}
	}
	if allSecrets {
		return model.KindSecrets
	}
	for _, k := range configTopLevel {
		if root.Get(k) != nil {
			return model.KindConfig
		}
	}
	return 0
}

// leafPaths lists the dotted paths of all scalar values, ignoring array
// indices ("EVM.Nodes.HTTPURL").
func leafPaths(v *model.Value, prefix string) []string {
	switch v.Kind {
	case model.TableValue:
		var out []string
		for _, k := range v.SortedKeys() {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			out = append(out, leafPaths(v.Table[k], p)...)
		}
		return out
	case model.ArrayValue:
		var out []string
		for _, item := range v.Array {
			out = append(out, leafPaths(item, prefix)...)
		}
		if len(v.Array) == 0 {
			out = append(out, prefix)
		}
		return out
	default:
		return []string{prefix}
	}
}

func underAny(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+".") {
			return true
		}
	}
	return false
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
