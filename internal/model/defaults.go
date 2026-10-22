package model

// Node defaults used by rules, verified against Chainlink node v2.69.0
// (see docs/research.md and ADR 0002). Keys are dotted paths; for keys inside
// arrays of tables the array name is used without an index ("EVM.Nodes.SendOnly").
//
// Integers are int64 because that is how the TOML decoder represents them.
//
// Sources:
//   - config: https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md
//   - secrets: https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md
//   - EVM.Enabled: chainlink-evm EVMConfig.IsEnabled (nil means enabled)
var configDefaults = map[string]any{
	"InsecureFastScrypt": false,

	"Insecure.DevWebServer":         false,
	"Insecure.OCRDevelopmentMode":   false,
	"Insecure.InfiniteDepthQueries": false,
	"Insecure.DisableRateLimiting":  false,

	"WebServer.AuthenticationMethod": "local",
	"WebServer.AllowOrigins":         "http://localhost:3000,http://localhost:6688",
	"WebServer.HTTPPort":             int64(6688),
	"WebServer.ListenIP":             "0.0.0.0",
	"WebServer.SecureCookies":        true,
	"WebServer.SessionTimeout":       "15m",

	"WebServer.TLS.HTTPSPort":     int64(6689),
	"WebServer.TLS.ForceRedirect": false,

	"WebServer.LDAP.ServerTLS":      true,
	"WebServer.LDAP.SessionTimeout": "15m0s",
	"WebServer.OIDC.SessionTimeout": "15m0s",

	"WebServer.RateLimit.Unauthenticated":       int64(5),
	"WebServer.RateLimit.UnauthenticatedPeriod": "20s",

	"Log.Level":           "info",
	"Database.LogQueries": false,

	"Tracing.Enabled": false,
	"Tracing.Mode":    "tls",

	"Telemetry.Enabled":                       false,
	"Telemetry.InsecureConnection":            false,
	"Telemetry.ChipIngressEndpoint":           "",
	"Telemetry.ChipIngressInsecureConnection": false,

	"AuditLogger.Enabled": false,

	"EVM.Enabled":                 true,
	"EVM.Nodes.SendOnly":          false,
	"EVM.Nodes.IsLoadBalancedRPC": false,
}

var secretsDefaults = map[string]any{
	"Database.AllowSimplePasswords": false,
}

// defaultFor returns the documented default for key in a document of kind k.
func defaultFor(k Kind, key string) (any, bool) {
	var table map[string]any
	switch k {
	case KindConfig:
		table = configDefaults
	case KindSecrets:
		table = secretsDefaults
	default:
		return nil, false
	}
	v, ok := table[key]
	return v, ok
}
