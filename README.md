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

**Settings** (`/ui/settings`) is the operator home for network/HTTPS, security, and backups. First boot works with no domain configured — private HTTP on `:8200` is unchanged.

### HTTPS (optional)

To expose the vault to cloud agents over TLS, configure a public hostname in **Settings**, then start the Compose `https` profile (Caddy terminates TLS and proxies to `agent-vault:8080`).

1. Open **Settings** → **Network & HTTPS**.
2. Enter your public hostname (FQDN only, e.g. `vault.example.com` — no `https://` or path).
3. In **Cloudflare DNS**, add **A** and/or **AAAA** records for that hostname pointing to beast’s public IP.
4. Set proxy status to **DNS only** (grey cloud) — **not** Proxied (orange cloud). Let’s Encrypt HTTP-01 requires direct reachability on ports 80/443.
5. Forward host ports **80** and **443** to the machine running Compose.
6. Wait for DNS to resolve publicly (`dig` / Cloudflare dashboard).
7. Check **Enable HTTPS**, save Settings (vault writes `Caddyfile` into the `caddy-config` volume).
8. Start or reload the HTTPS profile:

```bash
docker compose -f deploy/docker-compose.yml --profile https up -d
```

Agents and remote browsers can then use `https://<hostname>`; LAN access on `http://beast:8200` remains available. The Settings page shows the suggested public URL and apply command after save.

To rotate the passphrase after init, use **Change passphrase** in **Settings**, or:

```bash
vault change-passphrase --old 'current' --new 'replacement'
```

(`POST /v1/change-passphrase` with bearer auth). This rewraps the master key only — `unseal.key` and secrets are unchanged. **All bearer tokens are revoked** and a new root token is returned once (also written to `root.token` on the server). Update `AGENT_VAULT_TOKEN` / `~/.config/agent-vault` and remint agent tokens. After rotating on beast, update `~/.config/agent-vault/passphrase` so local notes stay accurate.

**Security:** Private HTTP on `:8200` is for the LAN only. For public access, use the `https` profile with a strong passphrase and per-agent bearer tokens — do not expose plain HTTP to the internet.

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

## Backup & export

On-demand disaster-recovery snapshots and portable encrypted exports. **Restore and import are CLI-only**; the Admin UI can download both artifacts.

| Artifact | Extension | Contents | Sealed OK? |
|----------|-----------|----------|------------|
| Snapshot | `.avs.tar.gz` | `vault.db` + `unseal.key` + manifest | Yes |
| Export | `.ave` | Secrets re-encrypted under a backup passphrase | No (vault must be unsealed) |

```bash
vault backup --out snapshot.avs.tar.gz          # download snapshot via API
vault restore --in snapshot.avs.tar.gz --data-dir ./data [--force]  # local filesystem; stop server first
vault export --passphrase '<backup-pass>' --out export.ave
vault import --passphrase '<backup-pass>' --in export.ave [--overwrite]
```

In the Admin UI, open **Settings** → **Backup** to **Download snapshot** or **Download export** (prompts for a backup passphrase). Treat `.avs.tar.gz` and `.ave` files as highly sensitive.

## MCP & agent skills

Agent integration docs and MCP examples live under `skills/`:

| Agent | Skill |
|-------|-------|
| Cursor | [`skills/cursor/SKILL.md`](skills/cursor/SKILL.md) — copy [`skills/cursor/mcp.json.example`](skills/cursor/mcp.json.example) into your MCP config |
| Claude Code | [`skills/claude/SKILL.md`](skills/claude/SKILL.md) |
| Hermes | [`skills/hermes/SKILL.md`](skills/hermes/SKILL.md) |

Set `AGENT_VAULT_URL` and `AGENT_VAULT_TOKEN` in the MCP server env. Ensure `vault-mcp` is on `PATH` (included in the Docker image at `/usr/local/bin/vault-mcp`).

## Security notes

- **Unseal key** — `/data/unseal.key` is written with mode `0600` at init and rewritten by `rotate-master`. Restrict volume access on the host; anyone with read access to this file can unseal the vault. Snapshot downloads include this key — treat snapshot files as full vault compromise material.
- **Root token** — Treat like a password. On server init it is written only to `/data/root.token` (mode `0600`), not to container logs. Mint agent tokens via `POST /v1/tokens`.
- **Passphrase** — Minimum **12 characters** for init, change-passphrase, and backup export. Required for Admin UI login and manual unlock. Login/unlock are rate-limited (5 failures / 15 minutes per client IP). Rotate with `vault change-passphrase` or Settings (does not invalidate `unseal.key`; **does revoke all bearer tokens** and mints a new root token). Unset `AGENT_VAULT_PASSPHRASE` after init.
- **Network** — Private HTTP on host port 8200 is for the LAN. Prefer binding only where needed (`AGENT_VAULT_BIND`). Public access should use the optional `https` Compose profile (Caddy + Let’s Encrypt) with Cloudflare **DNS only** (grey cloud). Set `AGENT_VAULT_TRUST_PROXY=1` when rate limits should use `X-Forwarded-For` behind Caddy.

## HTTP API

Search endpoint: `GET /v1/search` (query params `q`, `tag`, `type`). This path replaces `GET /v1/secrets:search` from the design doc for Go 1.22 `ServeMux` compatibility.

| Route | Auth | Purpose |
|-------|------|---------|
| `GET /health` | no | Liveness (`{"ok":true}` only) |
| `GET /ui/*` | session cookie | Admin UI (humans; passphrase login) |
| `POST /v1/unlock` | yes | Unlock with passphrase or unseal key |
| `POST /v1/lock` | yes | Seal vault |
| `POST /v1/change-passphrase` | yes | Rewrap master under a new passphrase |
| `POST /v1/rotate-master` | yes | New master key; rewrap secrets + `unseal.key` |
| `GET/POST /v1/secrets` | yes | List / create secrets |
| `GET/PUT/DELETE /v1/secrets/{name}` | yes | Read / update / delete |
| `GET /v1/search` | yes | Search by query, tag, type |
| `GET /v1/audit` | yes | Audit log |
| `GET /v1/backup/snapshot` | yes | Download snapshot archive |
| `POST /v1/backup/export` | yes | Download encrypted export |
| `POST /v1/tokens` | yes | Mint labeled API token |

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `8080` | HTTP listen port |
| `AGENT_VAULT_BIND` | `0.0.0.0` | Listen address (use `127.0.0.1` for host-local only) |
| `AGENT_VAULT_DATA_DIR` | `/data` | SQLite DB and key material directory |
| `AGENT_VAULT_UNSEAL_KEY` | `$DATA_DIR/unseal.key` | Auto-unseal key file path |
| `AGENT_VAULT_PASSPHRASE` | — | Passphrase for first-time init (≥12 chars; unset after init) |
| `AGENT_VAULT_INIT` | — | Set to `1` to allow init when DB is missing |
| `AGENT_VAULT_TRUST_PROXY` | — | Set to `1` to trust `X-Forwarded-For` for auth rate limits |
| `AGENT_VAULT_URL` | `http://localhost:8200` | CLI/MCP API base URL (Compose host port; use `https://<hostname>` when HTTPS is configured) |
| `AGENT_VAULT_TOKEN` | — | Bearer token for CLI/MCP |
| `AGENT_VAULT_CADDY_CONFIG_DIR` | `/caddy-config` (container) | Directory where Settings writes the generated `Caddyfile` |

## Phase 2 preview

Shipped on beast:

- Admin UI at `/ui` with **Settings** (network/HTTPS, security ops, backups)
- Optional Compose `https` profile (Caddy + Let’s Encrypt) for cloud agents
- Backup/export tooling (`vault backup` / `export` / `restore` / `import` and **Settings → Backup** in the UI)
- Passphrase change and master-key rotation (`vault change-passphrase` / `rotate-master` or Settings forms)
