# Agent Vault Backup & Export — Design Spec (Phase 2b)

**Date:** 2026-08-08  
**Status:** Ready for user review  
**Repo:** `agent-vault`  
**Depends on:** Phase 1 + Admin UI (2a); passphrase change / master rotation already on `main`  
**Host port:** 8200

## Purpose

Give the single vault owner on-demand **disaster-recovery snapshots** and **portable encrypted exports**, with CLI restore/import and Admin UI downloads — before exposing the vault more widely via HTTPS.

## Goals

1. Snapshot archive of on-disk encrypted state (`vault.db` + `unseal.key`) for fast host recovery.
2. Portable export of secret records re-encrypted under a backup passphrase.
3. CLI restore (snapshot) and import (export); Admin UI can download both, not restore/import.
4. Safe defaults: no plaintext leaks in logs/audit; refuse destructive restore without `--force`.

## Non-goals

- Scheduled/cron backups or cloud sync (`rclone` docs may come later).
- HTTPS / reverse proxy (Phase 2c, next).
- Per-secret rotation UI beyond existing `change-passphrase` / `rotate-master`.
- Including `root.token` in snapshots by default.
- Multi-user backup ACLs.

## Context (already shipped)

- Encrypted SQLite vault with seal/auto-unseal.
- Admin UI at `/ui` (session); agents on bearer `/v1`.
- `change-passphrase` and `rotate-master` revoke tokens and mint a new root token.

## Architecture

```text
                    ┌─ Snapshot (.avs.tar.gz)
Operator ──CLI/UI──┤    vault.db + unseal.key + manifest.json
                    │    OK while sealed; no secret plaintext
                    │
                    └─ Export (.ave)
                         unsealed → reveal → encrypt under backup passphrase

Restore / import: CLI only
  vault restore  → replace files in data dir (careful / --force)
  vault import   → create secrets into a running unsealed vault
```

## Artifact A — Snapshot

| Topic | Decision |
|-------|----------|
| Extension | `.avs.tar.gz` (gzip tar) |
| Contents | `vault.db`, `unseal.key`, `manifest.json` |
| Excluded | `root.token` (default) |
| Consistency | Prefer SQLite safe copy (`VACUUM INTO` temp file, then archive) when DB is open; else copy files if server stopped |
| Sealed OK? | Yes |
| Restore | CLI: extract into `--data-dir`; refuse if `vault.db` exists unless `--force`; operator restarts server |

`manifest.json` fields: `format` (`agent-vault-snapshot`), `version` (1), `created_at` (RFC3339), optional `source` string.

## Artifact B — Export

| Topic | Decision |
|-------|----------|
| Extension | `.ave` |
| Requires | Unsealed vault + backup passphrase (may differ from vault passphrase) |
| Crypto | Argon2id → AES-256-GCM over JSON payload of secrets |
| Payload | Array of `{name,type,username,secret,url,tags,notes,metadata}` |
| Header | Magic `AVE1`, kdf params, salt, nonce, ciphertext |
| Sealed | Reject with clear error / HTTP 503 |

## CLI

| Command | Role |
|---------|------|
| `vault backup [--out path]` | Create snapshot (via API or local data-dir mode) |
| `vault restore --in path --data-dir DIR [--force]` | Replace vault files from snapshot |
| `vault export --passphrase … [--out path]` | Create encrypted export (API; vault unsealed) |
| `vault import --passphrase … --in path [--overwrite]` | Import secrets into running vault via API |

Defaults: write to timestamped files in CWD if `--out` omitted. Never print secret values; do not echo backup passphrase.

**Local vs API:** `restore` is always local filesystem. `backup` may be API download or local archive of `--data-dir`. Prefer API for `backup`/`export`/`import` when `AGENT_VAULT_URL` + token are set (matches running server). Local `backup` of `--data-dir` supported for offline use.

## HTTP API (bearer)

| Method | Path | Behavior |
|--------|------|----------|
| GET | `/v1/backup/snapshot` | Download `.avs.tar.gz` |
| POST | `/v1/backup/export` | Body `{ "backup_passphrase": "..." }` → download `.ave` |

Audit actions: `backup_snapshot`, `backup_export` (no secret values, no passphrases).

## Admin UI

- Session + CSRF protected:
  - `GET /ui/api/backup/snapshot`
  - `POST /ui/api/backup/export` with backup passphrase
- UI controls: **Download snapshot**, **Download export** (prompt for backup passphrase).
- No upload / restore / import in the UI.

## Import / restore semantics

**Restore (snapshot)**
1. Server should be stopped (documented); CLI does not stop Docker for you.
2. Without `--force`, error if `data-dir/vault.db` exists.
3. With `--force`, replace `vault.db` and `unseal.key`.
4. Start server; auto-unseal if key present; remint tokens if needed (old `root.token` not in snapshot).

**Import (export)**
1. Target vault running and unsealed; bearer or CLI token auth.
2. Decrypt `.ave` with backup passphrase.
3. For each secret: `Create`; on name conflict skip unless `--overwrite` (then `Put`).
4. Audit `import` with counts (created/skipped/overwritten), never secret values.

## Security

- Treat `.ave` and snapshots containing `unseal.key` as highly sensitive.
- Backup passphrase never logged or audited.
- Export responses are file downloads; do not JSON-embed secrets in UI pages.
- `/v1` remains bearer-only; UI session cannot authorize `/v1` (unchanged).

## Testing

- Export encrypt/decrypt round-trip unit tests.
- Snapshot archive contains expected members + manifest.
- Integration: snapshot → restore temp dir → open/unseal → get secret.
- Integration: export → import into second vault → secret present; conflict skip/`--overwrite`.
- API auth + sealed export → 503.
- UI session can download snapshot/export with CSRF.
- Regression: `go test ./...`, `scripts/smoke.sh`, `scripts/smoke-ui.sh`.

## Deploy / docs

- README section: backup vs export, restore steps on the host, warn about token remint after snapshot restore.
- Skills: one line that humans can download backups from Admin UI; restore/import via CLI.

## Success criteria

1. CLI and Admin UI can produce snapshot and export downloads.
2. CLI restore from snapshot yields a working vault with prior secrets.
3. CLI import from export restores secrets into a vault.
4. No secret or backup-passphrase leakage in logs/audit/smoke output.
5. Existing agent `/v1` flows remain unchanged.

## Resolved decisions

| Topic | Decision |
|-------|----------|
| Artifacts | Snapshot + portable encrypted export |
| Trigger | On-demand only (no cron this slice) |
| UI | Download only; restore/import CLI-only |
| Approach | Two formats (Approach 1) |
| Next after this | HTTPS Compose profile (Phase 2c) |

## Sequencing note

After this slice ships and is verified on the host: **Phase 2c — HTTPS** reverse-proxy Compose profile for cloud agents.
