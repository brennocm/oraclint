# Phase 0 research: Chainlink node configuration security

> Status: approved 2026-10-22. Every key name and default below was checked against
> the node source and generated docs at the **target version** and links point to
> that exact tag.

## Target node version

**Chainlink node `v2.69.0`** (released 2026-10-19, latest stable at research time).

Primary sources, pinned to that tag:

| Source | Link |
|---|---|
| Generated config reference | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md |
| Generated secrets reference | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md |
| Config validation (`ValidateConfig`) | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/config/toml/types.go |
| Config loading / merge | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/services/chainlink/config_general.go |
| Insecure flag gating | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/services/chainlink/config_insecure.go |
| Password complexity | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/utils/password.go |
| Keystore unlock | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/cmd/key_store_authenticator.go |
| Web server startup | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/cmd/shell.go |
| HTTP router (CORS, pprof, metrics) | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/web/router.go |
| Environment variables | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/config/env/env.go |
| Official Dockerfile | https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/chainlink.Dockerfile |
| Running a node (Docker) | https://docs.chain.link/chainlink-nodes/v1/running-a-chainlink-node |
| Security best practices | https://docs.chain.link/chainlink-nodes/resources/best-security-practices |
| Strict TOML decoding (chainlink-common) | https://github.com/smartcontractkit/chainlink-common/blob/main/pkg/config/toml.go |

## How the node is configured

- **Two TOML documents.** Non-sensitive settings go in `config.toml` (`-config`/`-c`);
  credentials go in `secrets.toml` (`-secrets`/`-s`). They have different schemas.
- **Strict decoding.** Both are decoded with `DisallowUnknownFields()`. A secret key
  placed in `config.toml` (e.g. `[Password] Keystore`) makes the node **refuse to
  start**. A rule that detects it is therefore an *early warning*: by the time the
  node complains, the secret may already be committed.
- **Multiple config files.** `-c a.toml -c b.toml` is allowed; files are applied
  in order and **later values override earlier ones**. The `CL_CONFIG` env var
  (raw TOML) is always applied **last**.
- **Multiple secrets files** are merged too, but **overriding a secret is an error**
  (`OverrideError`), so each secret must be defined exactly once.
- **Secrets via env vars:** `CL_DATABASE_URL`, `CL_DATABASE_BACKUP_URL`,
  `CL_DATABASE_ALLOW_SIMPLE_PASSWORDS`, `CL_PASSWORD_KEYSTORE`, `CL_PASSWORD_VRF`,
  `CL_PYROSCOPE_AUTH_TOKEN`, `CL_PROMETHEUS_AUTH_TOKEN`, `CL_THRESHOLD_KEY_SHARE`.
- **Absent key = default.** The node fills unset keys from embedded defaults, so
  every rule must evaluate the *effective* value (explicit value, else default).

### Validation the node already enforces (no rule needed, or early warning only)

| Behaviour | Where | Consequence for oraclint |
|---|---|---|
| Any `[Insecure]` flag `true` is rejected on non-dev builds (`OCRDevelopmentMode` allowed on test builds) | `Insecure.validateConfig` | Early-warning rule only |
| `Database.AllowSimplePasswords = true` rejected on prod builds | `DatabaseSecrets.validateConfig` | Early-warning rule only |
| DB password must be ≥ 16 chars, no leading/trailing whitespace | `validateDBURL` + `VerifyPasswordComplexity` | **No rule** (node refuses) |
| Keystore password complexity enforced **only when the keystore is empty** (backwards compatibility) | `TerminalKeyStoreAuthenticator.Authenticate` | Real gap → rule |
| `Telemetry` enabled requires `CACertFile` unless `InsecureConnection = true` — **not** gated by build mode in code (docs say "dev only") | `Telemetry.ValidateConfig` | Real gap → rule |
| `Tracing.Mode = 'unencrypted'` requires a "local" `CollectorTarget`, but the check is only a hostname regex (`host:port`), so `collector.example.com:4317` passes | `isValidLocalURI` | Real gap → rule |
| `InsecureFastScrypt` is **not** gated by build mode | `shell_local.go` | Real gap → rule |

## Security-relevant keys

| Key | File | Default | Security impact |
|---|---|---|---|
| `InsecureFastScrypt` | config | `false` | Weak scrypt params for all keystores → offline brute force of encrypted private keys |
| `Insecure.DevWebServer` / `OCRDevelopmentMode` / `InfiniteDepthQueries` / `DisableRateLimiting` | config | `false` | Dev-only weakening of web server, OCR, GraphQL depth, rate limiting |
| `WebServer.HTTPPort` | config | `6688` | Plaintext HTTP listener; `0` disables it |
| `WebServer.ListenIP` | config | `0.0.0.0` | Bind address of plaintext listener |
| `WebServer.TLS.HTTPSPort` | config | `6689` | `0` disables HTTPS. Cert defaults to `<RootDir>/tls/server.crt` |
| `WebServer.TLS.ForceRedirect` | config | `false` | Redirect HTTP → HTTPS |
| `WebServer.SecureCookies` | config | `true` | `Secure` flag on session cookie |
| `WebServer.AllowOrigins` | config | `http://localhost:3000,http://localhost:6688` | CORS; `'*'` sets `AllowAllOrigins` (with `AllowCredentials: true`) |
| `WebServer.SessionTimeout` | config | `15m` | Idle session lifetime |
| `WebServer.AuthenticationMethod` | config | `local` | `local`, `ldap`, `oidc` |
| `WebServer.LDAP.ServerTLS` | config | `true` | Require `ldaps://` |
| `WebServer.MFA.RPID` / `RPOrigin` | config | unset | WebAuthn MFA for operator UI |
| `WebServer.RateLimit.Unauthenticated` / `UnauthenticatedPeriod` | config | `5` / `20s` | Login brute-force throttling |
| `Log.Level` | config | `info` | `debug` increases information disclosure |
| `Database.LogQueries` | config | `false` | Logs SQL statements at debug level |
| `Tracing.Enabled` / `Mode` / `CollectorTarget` | config | `false` / `tls` / unset | OTEL traces over plaintext |
| `Telemetry.InsecureConnection` / `ChipIngressInsecureConnection` | config | `false` / `false` | Telemetry over plaintext |
| `AuditLogger.ForwardToUrl` / `Headers` | config | unset | Audit events (and auth headers) to a remote URL |
| `EVM[].Nodes[].HTTPURL` / `WSURL` | config | — | RPC endpoints; providers often embed API keys in URL |
| `EVM[].Nodes[].SendOnly` / `IsLoadBalancedRPC` | config | `false` / `false` | RPC redundancy semantics |
| `Database.URL` / `BackupURL` | secrets | — | Postgres DSN incl. password and `sslmode` |
| `Database.AllowSimplePasswords` | secrets | `false` | Skip DB password complexity check |
| `Password.Keystore` / `Password.VRF` | secrets | — | Keystore encryption passwords |
| `Prometheus.AuthToken` | secrets | unset | If unset, `/metrics` is unauthenticated (pprof is always behind auth) |
| `WebServer.LDAP.ServerAddress`, `ReadOnlyUserPass`; `WebServer.OIDC.clientSecret`; `Mercury.Credentials.*`; `Threshold.ThresholdKeyShare`; `Pyroscope.AuthToken`; `CRE.Streams.*` | secrets | — | Must never appear in `config.toml` |

## Deployment patterns and their risks

- **Docker (official docs).** `smartcontract/chainlink:<version>`; docs publish
  `-p 6688:6688` and Postgres `-p 5432:5432` (docs note this is reachable from
  outside Docker) and use `sslmode=disable` "for local testing only". The docs
  state the `latest` tag does not work. Prod images run as UID:GID `14933:14933`
  (user `chainlink`); the Dockerfile `ARG CHAINLINK_USER` defaults to `root`
  for non-prod builds.
- **docker-compose with Postgres.** Typical mistakes: publishing 6688 and 5432 on
  `0.0.0.0`, passing `CL_DATABASE_URL`/`CL_PASSWORD_KEYSTORE`/`POSTGRES_PASSWORD` as
  literal `environment:` values, unpinned images.
- **Kubernetes/Helm.** Literal `env.value` secrets instead of `secretKeyRef`,
  `Service` of type `LoadBalancer`/`NodePort` exposing 6688, missing
  `securityContext` hardening.
- **Best practices page** recommends keeping 6688 closed to the internet and using
  an SSH tunnel; using TLS; running Postgres on separate hosts; redundant RPC
  connectivity behind load balancers.

## Proposed rule catalog (v1)

Legend — Status: **S** = stable, **E** = experimental (off by default, `--experimental`).
"EW" = early warning for something the node itself rejects on production builds.

### config.toml

| ID | Title | Sev | Detection (effective value; absent = default) | S/E |
|---|---|---|---|---|
| NS-KS-001 | Fast (insecure) scrypt for keystore | high | `InsecureFastScrypt = true` | S |
| NS-INS-001 | Development-only `[Insecure]` flag enabled (EW) | high | any of `Insecure.{DevWebServer,OCRDevelopmentMode,InfiniteDepthQueries,DisableRateLimiting} = true` | S |
| NS-WEB-001 | HTTPS listener disabled | medium | `WebServer.TLS.HTTPSPort = 0` and `WebServer.HTTPPort != 0` (default 6688) | S |
| NS-WEB-002 | Session cookies without `Secure` flag | medium | `WebServer.SecureCookies = false` | S |
| NS-WEB-003 | Wildcard CORS origin | medium | `WebServer.AllowOrigins = '*'` | S |
| NS-WEB-004 | HTTP not redirected to HTTPS | low | TLS explicitly configured (`TLS.CertPath`/`KeyPath` set or `HTTPSPort` set ≠ 0) and `ForceRedirect` false/absent and `HTTPPort != 0` | S |
| NS-WEB-005 | Long idle session timeout | low | `WebServer.SessionTimeout`, `LDAP.SessionTimeout` or `OIDC.SessionTimeout` > `1h` | S |
| NS-WEB-006 | LDAP without TLS | high | `AuthenticationMethod = 'ldap'` and `LDAP.ServerTLS = false` | S |
| NS-WEB-007 | Login rate limit relaxed | low | `RateLimit.Unauthenticated` / `UnauthenticatedPeriod` allows > 30 req/min (default 15/min) | E |
| NS-LOG-001 | Debug log level | low | `Log.Level = 'debug'` | S |
| NS-DB-001 | SQL query logging enabled | medium | `Database.LogQueries = true` | S |
| NS-TRC-001 | Traces exported unencrypted to remote collector | medium | `Tracing.Enabled = true`, `Mode = 'unencrypted'`, `CollectorTarget` host not loopback | S |
| NS-TEL-001 | Telemetry over insecure connection | medium | `Telemetry.Enabled = true` and `InsecureConnection = true`; or `ChipIngressInsecureConnection = true` with `ChipIngressEndpoint` set | S |
| NS-AUD-001 | Audit logs forwarded over plaintext | low | `AuditLogger.Enabled = true` and `ForwardToUrl` is `http://` to non-loopback host | S |
| NS-RPC-001 | Plaintext RPC connection | high | any `EVM.Nodes.HTTPURL`/`WSURL`/`HTTPURLExtraWrite` with `http://`/`ws://` to non-loopback/non-private host | S |
| NS-RPC-002 | Credential embedded in RPC URL | medium | userinfo in URL, or known provider key patterns (Infura `/v3/<32 hex>`, Alchemy `/v2/<key>`, QuickNode path token), or query param named like `key`/`apikey`/`token` | S |
| NS-RPC-003 | Single primary RPC node for chain | low | per `[[EVM]]` (enabled), count of `Nodes` with `SendOnly != true` == 1 and that node's `IsLoadBalancedRPC != true` | S |
| NS-SEC-001 | Secret value in config.toml (EW) | high | secrets-only keys present in a config file (`Password.*`, `Database.URL/BackupURL`, `Mercury.Credentials`, `Threshold`, `LDAP.ReadOnlyUserPass`, `OIDC.clientSecret`, `Prometheus/Pyroscope.AuthToken`, …) | S |
| NS-SEC-002 | Credential in AuditLogger headers | medium | `AuditLogger.Headers` entry with `Authorization`/token-like header name in config.toml | S |

### secrets.toml

| ID | Title | Sev | Detection | S/E |
|---|---|---|---|---|
| NS-DB-002 | Postgres TLS disabled for remote DB | high | `Database.URL`/`BackupURL` host not loopback/unix socket and `sslmode` ∈ {`disable`,`allow`} | S |
| NS-DB-003 | Postgres TLS not verified | low | remote host and `sslmode` absent (driver default `prefer`) or `prefer`/`require` (no cert verification) | E |
| NS-DB-004 | Simple DB passwords allowed (EW) | medium | `Database.AllowSimplePasswords = true` | S |
| NS-KS-002 | Weak keystore password | high | `Password.Keystore` or `Password.VRF` shorter than 16 chars or with leading/trailing whitespace (same rule as node; node only enforces for empty keystores) | S |
| NS-MET-001 | Unauthenticated Prometheus metrics | low | secrets file scanned, no `Prometheus.AuthToken` (may be provided via `CL_PROMETHEUS_AUTH_TOKEN`) | E |

### filesystem

| ID | Title | Sev | Detection | S/E |
|---|---|---|---|---|
| NS-FS-001 | Secrets file readable by group/others | medium | secrets file mode `& 0o077 != 0` (POSIX only; skipped on Windows) | S |

### docker-compose

| ID | Title | Sev | Detection | S/E |
|---|---|---|---|---|
| NS-DKR-001 | Operator UI port published on all interfaces | high | service using a `chainlink` image publishes container port 6688/6689 without host IP or with `0.0.0.0`/`::` | S |
| NS-DKR-002 | Postgres port published to host | medium | service with `postgres` image publishes 5432 (any host IP other than `127.0.0.1`) | S |
| NS-DKR-003 | Privileged container / host namespaces / dangerous capabilities | high | `privileged: true`, `network_mode: host`, `pid: host`, or `cap_add` ∋ {`ALL`,`SYS_ADMIN`,`NET_ADMIN`,`SYS_PTRACE`,`SYS_MODULE`,`DAC_READ_SEARCH`} | S |
| NS-DKR-004 | Node container runs as root | medium | chainlink service with `user: root`, `0`, `0:0` | S |
| NS-ENV-002 | Node secret as literal environment value | high | `environment:` contains `CL_DATABASE_URL`, `CL_DATABASE_BACKUP_URL`, `CL_PASSWORD_KEYSTORE`, `CL_PASSWORD_VRF`, `CL_*_AUTH_TOKEN`, `CL_THRESHOLD_KEY_SHARE`, `POSTGRES_PASSWORD` with a literal value (not `${VAR}` interpolation) | S |

### Kubernetes

| ID | Title | Sev | Detection | S/E |
|---|---|---|---|---|
| NS-K8S-001 | Privileged pod / host namespaces | high | `hostNetwork`/`hostPID`/`hostIPC: true` or container `privileged: true` | S |
| NS-K8S-002 | Container securityContext not hardened | medium | container (merged with pod-level `securityContext`) lacks `allowPrivilegeEscalation: false`, `runAsNonRoot: true` or `readOnlyRootFilesystem: true`; one finding per container listing the missing settings | S |
| NS-K8S-004 | Operator UI exposed by Service | high | `Service` type `LoadBalancer`/`NodePort` with `port`/`targetPort` 6688/6689 | S |
| NS-ENV-002 | (shared) Literal secret in `env[].value` | high | same variable list, `value:` instead of `valueFrom.secretKeyRef` | S |

### Shared (compose + k8s) and `.env`

| ID | Title | Sev | Detection | S/E |
|---|---|---|---|---|
| NS-IMG-001 | Unpinned container image | medium | image without tag, or `:latest`, and without `@sha256:` digest | S |
| NS-ENV-001 | Node secrets in a `.env` file | medium | `.env*` file defines one of the secret variables above with a non-empty value | S |

**Totals:** 35 unique rule IDs — 32 stable, 3 experimental (NS-WEB-007, NS-DB-003,
NS-MET-001). NS-ENV-002 and NS-IMG-001 apply to more than one target.

### Cut during review

- **NS-WEB-008 (WebAuthn MFA not configured):** MFA is enrolled per user account in
  the operator UI; the config only sets the relying-party ID. Static analysis cannot
  tell whether accounts actually use MFA, so the finding would be mostly noise.
- **NS-RPC-004 (no RPC provider diversity):** "same provider" can only be approximated
  from DNS names (CNAMEs, white-label endpoints, self-hosted proxies), which makes the
  rule unreliable; NS-RPC-003 already covers the single-endpoint case.
- **NS-K8S-003 (writable root filesystem)** was merged into NS-K8S-002 so that one
  container produces one securityContext finding instead of three.

### Investigated and not turned into rules

- **DB password complexity:** enforced by the node at startup → no rule.
- **`InsecurePPROFHeap`:** deprecated, "no effect, always enabled" → no rule.
- **pprof endpoints:** mounted under the authenticated router group → no rule.
- **Plaintext listener bound to `0.0.0.0`:** default, and required inside containers
  for port publishing → too noisy; covered by NS-DKR-001 / NS-K8S-004 instead.
- **Missing `user:` in compose:** official prod image already runs as UID 14933 →
  only explicit root is flagged (NS-DKR-004).
- **RPC API keys in secrets:** the node has no secrets field for RPC URLs. Remediation
  for NS-RPC-002 is to keep chain config in a separate, uncommitted config file or
  inject it via `CL_CONFIG` (applied last) from a secret store.
