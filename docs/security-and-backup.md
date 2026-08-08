# Security & backup

## Threat model (short)

Agent Vault assumes a **single trusted operator** on a host (beast), with many agents that should see secrets but not administer the vault.

| Asset | If leaked |
|-------|-----------|
| Passphrase | Unlock vault; UI login |
| `unseal.key` | Offline decrypt of DB (master key) |
| Admin bearer token | Full API including backups & token mint |
| Agent bearer token | Read/write secrets only |
| AVS2 snapshot + its passphrase | Full restore including unseal key |
| `.ave` export + its passphrase | All secret plaintext after decrypt |

## Built-in controls

- AES-256-GCM envelope encryption; Argon2id for passphrase / backup / snapshot KDFs
- Token hashes only at rest; scopes (`admin` / `agent`)
- Login & unlock rate limits; concurrent KDF gate
- Minimum passphrase length (12) for init, change, export, snapshot
- Security headers; `no-store` on revealed secrets and downloads
- HTTP timeouts and 1 MiB JSON body limit
- Optional IP allowlist; optional HTTPS via Caddy
- Root token not written to server logs (file only)

## Snapshots (disaster recovery)

| Format | Magic / shape | Passphrase | Contains |
|--------|---------------|------------|----------|
| **AVS2** (current) | `AVS2` + encrypted blob | Required (≥12) | `vault.db` + `unseal.key` |
| Legacy | gzip `.avs.tar.gz` | Not required | Same, plaintext in tar |

```bash
# Create
vault backup --passphrase 'snapshot-pass…' --out vault.avs

# Restore (stop server first if targeting the live data dir)
vault restore --in vault.avs --passphrase 'snapshot-pass…' --data-dir /path/to/data --force
```

Treat snapshot files like the combination of the database and the master key.

## Exports (portable secrets)

`.ave` files re-encrypt secret records under a **backup passphrase**. They do **not** include `unseal.key`. Useful for migrating secrets without cloning the whole vault identity.

```bash
vault export --passphrase 'export-pass…' --out secrets.ave
vault import --passphrase 'export-pass…' --in secrets.ave [--overwrite]
```

## Operator checklist

1. Strong passphrase (≥12; longer is better); unset `AGENT_VAULT_PASSPHRASE` after init.
2. Protect the Docker volume; mode `0600` on key files is necessary but not sufficient if the host is open.
3. Mint **agent** tokens per client; keep root offline or in an operator password manager.
4. Prefer LAN + HTTPS grey-cloud over exposing plain HTTP.
5. Use IP allowlist when agent egress IPs are known.
6. After `change-passphrase` or `rotate-master`, rotate every agent’s token.
7. Store snapshots/exports offline; do not commit them to git.

## Related

- [Concepts](concepts.md) — encryption & scopes
- [Install & ops](install-and-ops.md) — HTTPS and env
- [API](api.md) — admin backup routes
