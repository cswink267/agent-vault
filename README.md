# agent-vault

Encrypted secrets vault for agents. Runs on beast as a Docker service; agents reach it over the LAN via REST, CLI, or MCP.

## Quickstart (Docker)

### Build

```bash
docker build -t agent-vault:local .
```

Or build from source:

```bash
go build -o bin/vault-server ./cmd/vault-server
go build -o bin/vault ./cmd/vault
go build -o bin/vault-mcp ./cmd/vault-mcp
```

### Compose up

Canonical stack: `deploy/docker-compose.yml` (`build: ..`). From the repo root you can also use `docker-compose.yml` (`build: .`).

**First boot** — empty data volume requires init env vars:

```bash
export AGENT_VAULT_PASSPHRASE='choose-a-strong-passphrase'
export AGENT_VAULT_INIT=1

docker compose -f deploy/docker-compose.yml up --build -d
```

Watch logs for the root token (shown once). It is also written to `/data/root.token` inside the volume. After init succeeds, unset `AGENT_VAULT_INIT` for future restarts.

**Normal operation** — existing volume, auto-unseal via `/data/unseal.key`:

```bash
unset AGENT_VAULT_INIT
docker compose -f deploy/docker-compose.yml up -d
```

Health check:

```bash
curl -s http://localhost:8200/health
```

## Admin UI

Humans can manage secrets in a browser at **http://beast:8200/ui** (or `http://localhost:8200/ui` locally). Log in with the vault **passphrase** (same value used at init or unlock). The UI uses a session cookie and CSRF token for mutating requests; it does not replace bearer auth on `/v1`.

To rotate the passphrase after init, use **Change passphrase** in the Admin UI, or:

```bash
vault change-passphrase --old 'current' --new 'replacement'
```

(`POST /v1/change-passphrase` with bearer auth). This rewraps the master key only — `unseal.key` and secrets are unchanged. **All bearer tokens are revoked** and a new root token is returned once (also written to `root.token` on the server). Update `AGENT_VAULT_TOKEN` / `~/.config/agent-vault` and remint agent tokens. After rotating on beast, update `~/.config/agent-vault/passphrase` so local notes stay accurate.

**Security:** Admin UI is plain HTTP like the REST API — use only on the private LAN until the HTTPS slice lands. Do not expose port 8200 to the public internet.

Compose publishes host **8200** → container `8080` (beast `:8080` is already taken by filebrowser). Inside the container the server still binds `0.0.0.0:$PORT` (default `8080`). All vault state (`vault.db`, `unseal.key`, `root.token`) lives only on the `/data` volume.

### Local init (without container entrypoint)

```bash
vault init --data-dir ./data --passphrase 'your-passphrase'
AGENT_VAULT_DATA_DIR=./data PORT=8080 ./bin/vault-server
```

## CLI

Remote commands use the HTTP API:

```bash
export AGENT_VAULT_URL=http://beast:8200   # or http://localhost:8200 locally
export AGENT_VAULT_TOKEN=<token-from-init>

vault set --name openai.api_key --type api_key --secret "<value>" --tags cursor,openai
vault search openai
vault get openai.api_key
vault list
vault delete openai.api_key
vault change-passphrase --old '<current>' --new '<replacement>'
vault rotate-master --passphrase '<current>'
```

`rotate-master` generates a new master key, rewraps every secret DEK, rewrites `unseal.key`, and revokes bearer tokens (returns a new root token once). Passphrase stays the same unless you also run `change-passphrase`.

## MCP & agent skills

Agent integration docs and MCP examples live under `skills/`:

| Agent | Skill |
|-------|-------|
| Cursor | [`skills/cursor/SKILL.md`](skills/cursor/SKILL.md) — copy [`skills/cursor/mcp.json.example`](skills/cursor/mcp.json.example) into your MCP config |
| Claude Code | [`skills/claude/SKILL.md`](skills/claude/SKILL.md) |
| Hermes | [`skills/hermes/SKILL.md`](skills/hermes/SKILL.md) |

Set `AGENT_VAULT_URL` and `AGENT_VAULT_TOKEN` in the MCP server env. Ensure `vault-mcp` is on `PATH` (included in the Docker image at `/usr/local/bin/vault-mcp`).

## Security notes

- **Unseal key** — `/data/unseal.key` is written with mode `0600` at init and rewritten by `rotate-master`. Restrict volume access on the host; anyone with read access to this file can unseal the vault.
- **Root token** — Treat like a password. Save from init logs or `/data/root.token`; mint scoped tokens via `POST /v1/tokens` for agents.
- **Passphrase** — Required for init, Admin UI login, and manual unlock (`POST /v1/unlock`). Rotate with `vault change-passphrase` or the Admin UI form (does not invalidate `unseal.key`; **does revoke all bearer tokens** and mints a new root token). Do not commit it to git or bake it into images.
- **Network** — Phase 1 serves plain HTTP on the private network. Do not expose host port 8200 (or the container port) to the public internet without TLS.

## HTTP API

Search endpoint: `GET /v1/search` (query params `q`, `tag`, `type`). This path replaces `GET /v1/secrets:search` from the design doc for Go 1.22 `ServeMux` compatibility.

| Route | Auth | Purpose |
|-------|------|---------|
| `GET /health` | no | Liveness + sealed status |
| `GET /ui/*` | session cookie | Admin UI (humans; passphrase login) |
| `POST /v1/unlock` | yes | Unlock with passphrase or unseal key |
| `POST /v1/lock` | yes | Seal vault |
| `POST /v1/change-passphrase` | yes | Rewrap master under a new passphrase |
| `POST /v1/rotate-master` | yes | New master key; rewrap secrets + `unseal.key` |
| `GET/POST /v1/secrets` | yes | List / create secrets |
| `GET/PUT/DELETE /v1/secrets/{name}` | yes | Read / update / delete |
| `GET /v1/search` | yes | Search by query, tag, type |
| `GET /v1/audit` | yes | Audit log |
| `POST /v1/tokens` | yes | Mint labeled API token |

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `8080` | HTTP listen port |
| `AGENT_VAULT_DATA_DIR` | `/data` | SQLite DB and key material directory |
| `AGENT_VAULT_UNSEAL_KEY` | `$DATA_DIR/unseal.key` | Auto-unseal key file path |
| `AGENT_VAULT_PASSPHRASE` | — | Passphrase for first-time init |
| `AGENT_VAULT_INIT` | — | Set to `1` to allow init when DB is missing |
| `AGENT_VAULT_URL` | `http://localhost:8200` | CLI/MCP API base URL (Compose host port) |
| `AGENT_VAULT_TOKEN` | — | Bearer token for CLI/MCP |

## Phase 2 preview

Planned after Phase 1 is verified on beast:

- HTTPS reverse-proxy Compose profile (Caddy/nginx + TLS) for cloud agents
- Backup and export tooling
- Secret rotation helpers

Admin UI is available at `/ui` for human operators; agents should continue using MCP/CLI with bearer tokens.
