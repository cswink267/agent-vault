# Security & backup

Practical security picture for a single-operator vault: what to protect, what the software already does, and how to back up without painting yourself into a corner.

## Threat model (short)

Agent Vault assumes **one trusted operator** on a host, plus many agents that should read/write secrets but **not** administer the vault.

| If this leaks… | An attacker can… |
|----------------|------------------|
| Passphrase | Unlock the vault and log into the Admin UI |
| `unseal.key` | Decrypt the database offline (it *is* the master key) |
| Admin bearer token | Full API: backups, token mint, rotate, lock |
| Agent bearer token | Read and write secrets only |
| AVS2 snapshot + its passphrase | Full restore, including `unseal.key` |
| `.ave` export + its passphrase | Recover all secret plaintext after decrypt |

## Built-in controls

You get these without turning anything on:

- AES-256-GCM envelope encryption; Argon2id for passphrase / backup / snapshot KDFs
- Token hashes only at rest; scopes (`admin` / `agent`)
- Login and unlock rate limits; concurrent KDF gate
- Minimum passphrase length (12) for init, change, export, and snapshot
- Security headers; `Cache-Control: no-store` on revealed secrets and downloads
- HTTP timeouts and a 1 MiB JSON body limit
- Root token written to a file only — not to server logs

Optional controls **you** enable:

| Control | Default | How you turn it on |
|---------|---------|-------------------|
| IP allowlist | **Allow all** (empty) | Settings → enter IPs/CIDRs yourself |
| Public HTTPS | Off | Settings hostname + Compose `--profile https` |

Agent Vault will not invent an allowlist for you. Leave it empty unless you know which client IPs should reach the vault.

## Snapshots vs exports (pick the right one)

| | **Snapshot (AVS2)** | **Export (`.ave`)** |
|--|---------------------|---------------------|
| Purpose | Disaster recovery of *this* vault | Move/copy secret *values* |
| Contains | `vault.db` + `unseal.key` | Secret records only |
| Passphrase | Required (≥12) | Required (≥12) |
| Restores identity | Yes (same vault after restore) | No — merges into whatever vault you import into |
| UI | Settings → download snapshot | Settings → download export |
| CLI | `vault backup` / `vault restore` | `vault export` / `vault import` |

### Snapshots (disaster recovery)

| Format | Shape | Passphrase | Contains |
|--------|-------|------------|----------|
| **AVS2** (current) | `AVS2` + encrypted blob | Required (≥12) | `vault.db` + `unseal.key` |
| Legacy | gzip `.avs.tar.gz` | Not required | Same files, plaintext inside the tar |

```bash
# Create
vault backup --passphrase 'snapshot-pass…' --out vault.avs

# Restore (stop the server first if targeting the live data dir)
vault restore --in vault.avs --passphrase 'snapshot-pass…' --data-dir /path/to/data --force
```

Treat an AVS2 file the way you would treat the database **and** the master key sitting in one envelope.

### Exports (portable secrets)

`.ave` files re-encrypt secret records under a **backup passphrase**. They do **not** include `unseal.key`. Use them to migrate secrets to another vault without cloning the whole identity.

```bash
vault export --passphrase 'export-pass…' --out secrets.ave
vault import --passphrase 'export-pass…' --in secrets.ave [--overwrite]
```

The vault must be **unsealed** to export. Import merges into the current vault (`--overwrite` replaces conflicting names).

## Operator checklist

1. Use a strong passphrase (≥12; longer is better). Unset `AGENT_VAULT_PASSPHRASE` after first init.
2. Protect the Docker volume. Mode `0600` on key files helps, but anyone with root on the host can still read them.
3. Mint **agent** tokens per client. Keep the root admin token offline or in your password manager.
4. Prefer private-network access, or HTTPS with grey-cloud DNS, over exposing plain HTTP on the public internet.
5. Leave the IP allowlist **empty** unless you have stable client IPs and understand the Docker NAT gotcha ([install guide](install-and-ops.md)).
6. After `change-passphrase` or `rotate-master`, remint and redistribute every agent token.
7. Store snapshots and exports offline. Do not commit them to git.
8. Practice a restore once on a throwaway data directory so recovery is not theoretical.

## Related

- [Concepts](concepts.md) — encryption and scopes  
- [Install & ops](install-and-ops.md) — HTTPS, allowlist, troubleshooting  
- [Admin UI](admin-ui.md) — downloading backups from Settings  
- [API](api.md) — admin backup routes  
