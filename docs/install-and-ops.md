# Install & operations

This guide is for the human who runs Agent Vault on a host. Follow it for first boot, HTTPS, upgrades, and the problems people actually hit.

## Requirements

- Docker + Docker Compose (recommended), **or** Go 1.25+ to build binaries yourself
- Persistent disk for the data volume (`vault.db`, `unseal.key`, and optionally `root.token`)
- For public HTTPS: a DNS name, ports **80** and **443** free/forwarded, and DNS that can stay on **DNS only** (grey cloud) during certificate issuance

## Build

```bash
# Container image
docker build -t agent-vault:local .

# Or native binaries
go build -o bin/vault-server ./cmd/vault-server
go build -o bin/vault ./cmd/vault
go build -o bin/vault-mcp ./cmd/vault-mcp
```

Compose files:

- Canonical: `deploy/docker-compose.yml` (`build: ..`)
- Repo-root convenience: `docker-compose.yml` (`build: .`)

Host port **8200** maps to container **8080**. Keep using `8200` in browser bookmarks and `AGENT_VAULT_URL`.

## First boot (empty volume)

Pick a strong passphrase (**at least 12 characters**). You will need it for the Admin UI forever (unless you change it later).

```bash
export AGENT_VAULT_PASSPHRASE='choose-a-strong-passphrase'
export AGENT_VAULT_INIT=1

docker compose -f deploy/docker-compose.yml up --build -d
```

What happens on first boot:

1. The server creates `/data/vault.db`, writes `/data/unseal.key` (mode `0600`), and mints a root **admin** token.
2. That root token is written to `/data/root.token` (mode `0600`). Current builds do **not** print it in container logs.
3. Copy the token out once, store it somewhere safe (password manager), then remove `AGENT_VAULT_INIT` / `AGENT_VAULT_PASSPHRASE` from the environment for future boots.

```bash
docker compose -f deploy/docker-compose.yml exec agent-vault cat /data/root.token
```

Every restart after that:

```bash
unset AGENT_VAULT_INIT
unset AGENT_VAULT_PASSPHRASE   # not needed after init; do not leave it in compose env long-term
docker compose -f deploy/docker-compose.yml up -d
```

Health check:

```bash
curl -s http://localhost:8200/health
# {"ok":true}
```

Admin UI: open `http://localhost:8200/ui` (or `http://<hostname>:8200/ui` on your network) and log in with the passphrase.

## Local run (no Docker)

```bash
vault init --data-dir ./data --passphrase 'your-passphrase-here'
export AGENT_VAULT_DATA_DIR=./data
export PORT=8080
./bin/vault-server
```

In another shell:

```bash
export AGENT_VAULT_URL=http://localhost:8080
export AGENT_VAULT_TOKEN=$(cat ./data/root.token)
vault list
```

## Day-2: mint agent tokens

Do **not** give every agent the root token. Mint one labeled agent token per client:

```bash
export AGENT_VAULT_URL=http://localhost:8200
export AGENT_VAULT_TOKEN=<admin-token>

vault token create --label my-ide --scope agent
vault token create --label cicd --scope agent
vault token list
```

Save each returned `avt_…` value only in that agent’s secret store / MCP env. Revoke when retired:

```bash
vault token revoke --id <token-id-from-list>
```

## HTTPS for cloud agents (optional)

Goal: cloud agents reach `https://vault.example.com` while private access on port **8200** still works.

1. Open Admin UI → **Settings → Network & HTTPS**.
2. Set public hostname (FQDN only, e.g. `vault.example.com` — no `https://`).
3. In Cloudflare (or your DNS): **A/AAAA** → this host’s public IP, proxy **DNS only** (grey cloud).
4. Forward host ports **80** and **443** (they must not already be taken by another service).
5. Wait until public DNS resolves to this host.
6. Check **Enable HTTPS**, save. The vault writes a `Caddyfile` into the shared `caddy-config` volume.
7. Start the HTTPS profile:

```bash
docker compose -f deploy/docker-compose.yml --profile https up -d
```

When Caddy sits in front of the vault, set `AGENT_VAULT_TRUST_PROXY=1` on the vault service so rate limits and the IP allowlist see the real client IP from `X-Forwarded-For`.

Agents then use:

```bash
export AGENT_VAULT_URL=https://vault.example.com
export AGENT_VAULT_TOKEN=<agent-token>
```

## IP allowlist (optional — off by default)

**Default: all IPs are allowed.** The allowlist field starts empty and stays empty until you change it in Settings. Agent Vault never fills in a restrictive list for you.

When you *do* set IPs/CIDRs:

- Only listed clients can reach `/ui` and `/v1`.
- `/health` stays open for monitoring.
- Behind Caddy, enable `AGENT_VAULT_TRUST_PROXY=1` or the vault will see Caddy’s internal IP instead of the client.

**Docker NAT gotcha:** traffic published as `localhost:8200` often arrives with a Docker bridge IP (for example `172.x`), not `127.0.0.1`. If you allowlist only `127.0.0.1/32`, you can lock yourself out from the host while the vault still looks “up” on `/health`.

If you lock yourself out:

1. Call the Settings API from a process that shares the vault container’s network namespace (so the client IP is `127.0.0.1`), **or**
2. Clear the `ip_allowlist` setting in the SQLite database and restart the container.

Prefer allowing your whole LAN CIDR (for example `10.0.0.0/24`) rather than a single loopback address when the vault runs in Docker.

## Useful environment variables

| Variable | Default | Notes |
|----------|---------|-------|
| `PORT` | `8080` | Listen port inside the process |
| `AGENT_VAULT_BIND` | `0.0.0.0` | Use `127.0.0.1` for host-local only |
| `AGENT_VAULT_DATA_DIR` | `/data` | DB + keys |
| `AGENT_VAULT_UNSEAL_KEY` | `$DATA_DIR/unseal.key` | Auto-unseal path |
| `AGENT_VAULT_INIT` | — | `1` only on first empty boot |
| `AGENT_VAULT_PASSPHRASE` | — | Init only; unset afterward |
| `AGENT_VAULT_CADDY_CONFIG_DIR` | `/caddy-config` | Where Settings writes `Caddyfile` |
| `AGENT_VAULT_TRUST_PROXY` | — | `1` to trust `X-Forwarded-For` |
| `AGENT_VAULT_PRIVATE_BASE_URL` | `http://localhost:8200` | Shown in Settings status |
| `AGENT_VAULT_URL` | `http://localhost:8200` | Client base URL (CLI/MCP) |
| `AGENT_VAULT_TOKEN` | — | Client bearer token |

## Passphrase & master rotation

```bash
# Rewrap master under a new passphrase (tokens revoked; new root returned once)
vault change-passphrase --old 'current-passphrase' --new 'replacement-passphrase'

# New master key + rewrite unseal.key + rewrap all secrets (tokens revoked)
vault rotate-master --passphrase 'current-passphrase'
```

Both are also under **Settings → Security** in the Admin UI. After either operation:

1. Save the new root token somewhere safe.
2. Remint and redistribute every agent token.
3. Update CLI/MCP env everywhere that still has an old `avt_…` value.

## Smoke checks

From a clone of this repo:

```bash
bash scripts/smoke.sh
bash scripts/smoke-ui.sh
bash scripts/smoke-backup.sh
bash scripts/smoke-settings.sh
```

## Upgrading

1. `git pull` (or otherwise get the new tree).
2. `docker compose -f deploy/docker-compose.yml up -d --build`
3. SQLite migrations (for example the token `scope` column) run automatically on open.
4. Remint agent tokens only if you rotated passphrase/master or revoked tokens.
5. Refresh local `vault` / `vault-mcp` binaries if you keep copies outside the container (for example on your `PATH`).

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `{"ok":true}` but UI/API return `403` | IP allowlist set; your client IP is not listed | Clear or widen the allowlist (see above) |
| Settings save fails writing Caddyfile | `/caddy-config` volume not writable by uid 1000 | Image should own `/caddy-config` as `vault`; chown the volume if an old deploy left it root-owned |
| HTTPS profile won’t start | Host ports 80/443 already in use | Free those ports or skip the `https` profile and stay on private `:8200` |
| Cert never issues | Cloudflare orange-cloud / wrong DNS | Set DNS only (grey cloud); confirm A/AAAA points at this host |
| `503` on secret routes | Vault sealed | Unlock with passphrase in UI or `vault unlock` |
| Agent gets `403` on backup/token routes | Token is `agent` scope | Expected — mint an admin token only for operator tasks |
| Forgot passphrase | No recovery from passphrase alone | Restore from an AVS2 snapshot (needs snapshot passphrase) or from a known `unseal.key` + DB backup |
| Root token lost | File deleted / never copied | If vault is unsealed and you still have an admin token, mint a new admin token; otherwise restore from snapshot |
