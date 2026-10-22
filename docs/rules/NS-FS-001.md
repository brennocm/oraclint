# NS-FS-001: Secrets file accessible by group or others

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | secrets | stable | CWE-732 |

## Description

Fires when a secrets file has any group or other permission bit set
(`mode & 0o077 != 0`), for example `0644` or `0640`.

POSIX systems only. On Windows, Go does not expose ACLs as permission bits,
so the rule does not run there. Merged targets have no single file mode and
are skipped.

## Why it matters

`secrets.toml` holds the database URL with its password and the keystore
password. If other local users or services can read it, a compromise of any of
them becomes a compromise of the node's keys. The node itself keeps its root
directory at `0700` for the same reason.

## Vulnerable example

```sh
$ ls -l secrets.toml
-rw-r--r-- 1 chainlink chainlink 210 secrets.toml
```

## Fixed example

```sh
chmod 600 secrets.toml
chown chainlink:chainlink secrets.toml
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md
- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#rootdir
