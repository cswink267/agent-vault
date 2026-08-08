# Agent Vault — Design Spec

**Date:** 2026-08-08  
**Status:** Ready for user review  
**Repo:** `agent-vault`

## Purpose

Build a from-scratch, single-user encrypted vault that Cursor, Claude Code, Hermes, and other applications can share. When one agent stores a private key or login, the others can find and use it by the same name. Deployed on **beast** as a Docker container. No third-party password managers (e.g. Vaultwarden).

## Goals

1. Cross-agent shared secrets with stable names and structured records.
2. Installable skills (and MCP/CLI) so agents automatically use the vault for private data.
3. Strong encryption at rest with seal/unseal and auto-unseal on a trusted host.
4. Hybrid reachability: private network by default; optional HTTPS for cloud agents (Phase 2).
5. Simple one-container deploy suitable for beast.

## Non-goals (v1)

- Multi-user ACLs or per-secret sharing policies.
- Admin web UI.
- Incorporating Vaultwarden, Bitwarden, HashiCorp Vault, or similar products.
- File attachments / binary blobs (PEM files as secret *text* are fine).
- High-availability clustering.

## Trust model

- **Single user on beast** — one human owner; all agents share one vault.
- Agent runtimes authenticate with API tokens (full access in v1).
- Tokens may be one shared token or labeled per runtime (`cursor`, `claude`, `hermes`).
- Host compromise of beast + unseal key material can reveal secrets; mitigate with volume permissions, optional seal when unused, and Phase 2 HTTPS hardening.

## Architecture

```text
Agents (Cursor / Claude Code / Hermes / apps)
  skills → CLI and/or MCP clients
           │
           ▼  LAN / Tailscale  (HTTPS optional in Phase 2)
┌──────────────────────────────────────────┐
│ agent-vault container                    │
│  HTTP API  →  Crypto/Seal  →  SQLite     │
│  token auth · audit log · health         │
└──────────────────────────────────────────┘
```

- **One Go binary** (server) in Docker binds `0.0.0.0:$PORT`.
- **CLI** (`vault`) and **MCP server** (`vault-mcp`) are thin clients of the HTTP API.
- Skills do not store secrets; they instruct agents when/how to call vault tools.

### Components

| Component | Responsibility |
|-----------|----------------|
| `vault-server` | REST API, auth, seal state, audit |
| `internal/crypto` | Argon2id, AES-256-GCM, envelope encryption |
| `internal/store` | SQLite schema, CRUD, search |
| `internal/auth` | API token create/verify (hashed at rest) |
| `internal/audit` | Append-only access events |
| `vault` CLI | User/agent command surface |
| `vault-mcp` | MCP tool surface for IDE agents |
| `skills/*` | Auto-use instructions per runtime |

## Data model

Structured credential records:

| Field | Storage | Notes |
|-------|---------|-------|
| `id` | plaintext | UUID |
| `name` | plaintext | Unique slug, e.g. `openai.api_key` |
| `type` | plaintext | `api_key` \| `login` \| `ssh_key` \| `token` \| `note` |
| `username` | encrypted | Optional |
| `secret` | encrypted | Required sensitive value |
| `url` | plaintext | Optional |
| `tags` | plaintext | JSON array for search |
| `notes` | plaintext | Non-secret context |
| `metadata` | plaintext | JSON object for app extras |
| `created_at` / `updated_at` | plaintext | RFC3339 timestamps |
| `version` | plaintext | Increments when secret/username change |

**List/search responses omit `secret` and `username` unless reveal is requested** (`GET` with reveal flag, or `vault get`).

## Crypto & seal lifecycle

1. **Init (local bootstrap, once):** `vault init` (or container entrypoint on empty data dir) writes the SQLite DB on the data volume, generates master key material, wraps it with an Argon2id-derived key from the passphrase, writes the auto-unseal key file, and mints the first API token (printed once). There is no public unauthenticated remote init endpoint.
2. **Envelope encryption:** per-record random DEK; encrypt `secret` and, when present, `username` with AES-256-GCM; wrap DEK with master key; store ciphertext + nonce + wrapped DEK. Absent optional fields are stored as SQL NULL (not encrypted empty strings).
3. **Boot:** process starts **sealed** (master key not in memory). API token verification still works while sealed (token hashes are not encrypted with the master key).
4. **Auto-unseal:** if configured unseal key file/env is present and valid, load master key and mark unsealed.
5. **Manual unlock/lock:** authenticated API/CLI unlock (passphrase or unseal key material) or lock to clear master key from memory.
6. **Sealed behavior:** `GET /health` works; secret mutations/reads/search/reveal return `503` with a clear sealed error.

## HTTP API

Base path `/v1`. Authorization: `Authorization: Bearer <token>`.

| Method | Path | Behavior |
|--------|------|----------|
| GET | `/health` | Liveness + `sealed` boolean (no auth required) |
| POST | `/v1/unlock` | Unlock with passphrase or unseal key material |
| POST | `/v1/lock` | Seal vault |
| GET | `/v1/secrets` | List (no secret material) |
| POST | `/v1/secrets` | Create |
| GET | `/v1/secrets/{name}` | Get; `?reveal=1` includes decrypted fields |
| PUT | `/v1/secrets/{name}` | Update |
| DELETE | `/v1/secrets/{name}` | Delete |
| GET | `/v1/secrets:search` | Query `q`, `tag`, `type` |
| GET | `/v1/audit` | Recent events |
| POST | `/v1/tokens` | Mint labeled token (authenticated) |

### Error codes

- `400` validation error  
- `401` missing/invalid token  
- `404` unknown secret  
- `409` duplicate name  
- `503` sealed  

### Audit events

Record: timestamp, token label, action (`get_reveal`, `set`, `delete`, `unlock`, `lock`, `search`, …), secret name when applicable. **Never log secret values.**

## CLI

Commands:

- `vault init` / `vault unlock` / `vault lock`
- `vault set` / `vault get` / `vault list` / `vault search` / `vault delete`
- `vault audit` / `vault token create`

Config via env: `AGENT_VAULT_URL`, `AGENT_VAULT_TOKEN` (and optional config file under `~/.config/agent-vault/`).

## MCP tools

| Tool | Maps to |
|------|---------|
| `vault_search` | search |
| `vault_list` | list |
| `vault_get` | get (reveal) |
| `vault_set` | create/update |
| `vault_delete` | delete |

MCP process reads the same URL/token env vars. Runs in the agent environment; talks to the beast-hosted API.

## Agent skills (auto-use)

Ship skill packs under `skills/{cursor,claude,hermes}/`:

1. If the user provides a password, API key, token, or login → store with `vault_set` / `vault set`; do not leave secrets only in chat or repo files.
2. If a task needs credentials → `vault_search` / `vault get` first; do not re-ask if present.
3. Never echo full secrets into logs, commits, or PR bodies; refer by name (`vault:openai.api_key`).
4. Prefer MCP when available; fall back to CLI.

Cursor also gets an MCP config fragment; Claude Code and Hermes get skill + CLI setup notes.

## Docker deploy (beast, v1)

- `Dockerfile` multi-stage Go build → minimal runtime image.
- `deploy/docker-compose.yml`: one service, named volume `vault-data`, env for port, data dir, unseal key path.
- Bind `0.0.0.0:$PORT`.
- State only on the volume (ephemeral container FS).
- Default exposure: private (LAN/Tailscale). No public proxy in v1.

## Reachability

| Mode | When |
|------|------|
| Private (default) | Agents on beast, LAN, or Tailscale to vault port |
| HTTPS (Phase 2) | Cloud Cursor/Claude agents; Caddy/nginx profile + TLS |

## Testing strategy

- **Unit:** crypto round-trip, wrap/unwrap, seal/unseal, token hashing.
- **API integration:** CRUD, search, auth failures, sealed `503`.
- **CLI smoke:** against ephemeral test server.
- **Fixtures:** skill markdown present and references correct tool/CLI names.

## Phased delivery

### Phase 1 — Core MVP (this implementation cycle)

Encrypted SQLite store, seal/auto-unseal, REST API, CLI, MCP server, skills for Cursor/Claude/Hermes, Docker Compose, audit log, tests.

### Phase 2 — Ops pack (after Phase 1 verified working)

HTTPS reverse-proxy compose profile, backup/export, secret rotation helpers. Admin UI remains optional and out of scope unless re-requested.

## Repository layout

```text
cmd/vault-server/
cmd/vault/
cmd/vault-mcp/
internal/api/
internal/crypto/
internal/store/
internal/auth/
internal/audit/
skills/cursor/
skills/claude/
skills/hermes/
deploy/docker-compose.yml
Dockerfile
docs/superpowers/specs/
README.md
```

## Success criteria (Phase 1)

1. `docker compose up` on beast yields a healthy vault.
2. CLI can init, set, get, search a secret.
3. MCP tools perform the same operations against that server.
4. A secret written via Cursor-oriented flow is readable via Claude/Hermes CLI or MCP using the same name.
5. Sealed vault rejects secret access; auto-unseal restores access with the key file.
6. Audit log records reveal/set/delete without secret values.
7. Automated tests cover crypto + API critical paths.

## Open decisions (resolved)

| Topic | Decision |
|-------|----------|
| Trust model | Single-user |
| Reachability | Hybrid (private default, HTTPS later) |
| Integration | MCP + CLI |
| Record shape | Structured credentials (no attachments in v1) |
| Crypto UX | Passphrase + sealed mode + auto-unseal key |
| v1 scope | Core MVP; ops pack after verification |
| Stack | Go monolith + SQLite + AES-GCM |
