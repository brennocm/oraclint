# JSON output format

`oraclint scan --format json` writes one JSON document. The format is versioned
by `schema_version`; any breaking change (removing or renaming a field, changing
a type or meaning) increments it. Adding fields is not a breaking change, so
consumers should ignore fields they do not know.

## Schema version 1

```json
{
  "schema_version": "1",
  "tool": {
    "name": "oraclint",
    "version": "v0.1.0",
    "information_uri": "https://github.com/brennocm/oraclint"
  },
  "summary": {
    "files_scanned": 3,
    "total": 2,
    "by_severity": { "critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0 },
    "suppressed": 0,
    "disabled_rules": []
  },
  "findings": [
    {
      "rule_id": "NS-RPC-001",
      "severity": "high",
      "title": "RPC endpoint uses unencrypted transport",
      "message": "EVM chain \"1\" node \"primary\": WSURL uses unencrypted ws:// to rpc.example.com",
      "location": { "file": "node/config.toml", "line": 6, "column": 1 },
      "remediation": "Use https:// and wss:// endpoints, or keep the RPC node on a private network."
    }
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | Currently `"1"`. |
| `tool.version` | string | oraclint version that produced the report. |
| `summary.files_scanned` | integer | Files analyzed (merged config files count once). |
| `summary.total` | integer | Number of entries in `findings`. |
| `summary.by_severity` | object | Counts of active (unsuppressed) findings for `critical`, `high`, `medium`, `low`, `info`. |
| `summary.suppressed` | integer | Findings suppressed inline or by the config file (still listed in `findings`). |
| `summary.disabled_rules` | array | Rules turned off by the config file: `rule_id`, `reason`, `source`. Always present. |
| `findings[].suppression` | object | Present on suppressed findings: `kind` (`inline` or `config`), `reason`, `source` location. |
| `findings` | array | Always present; `[]` when there are no findings. Sorted by file, line, column, rule ID. |
| `findings[].rule_id` | string | Stable rule ID such as `NS-KS-001`, or `parse-error` for files that could not be scanned. |
| `findings[].severity` | string | `critical`, `high`, `medium`, `low` or `info`. |
| `findings[].message` | string | Specific to the occurrence. Never contains secret values. |
| `findings[].location.file` | string | Path as given on the command line, with forward slashes. |
| `findings[].location.line` / `column` | integer | 1-based. Omitted when the finding concerns the whole file. |
| `findings[].remediation` | string | Short fix; see `oraclint rules explain <ID>` for details. |

Output is deterministic: the same input produces byte-identical JSON.
