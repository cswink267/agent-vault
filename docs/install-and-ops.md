# Install & operations

## Requirements

- Docker + Docker Compose (recommended on beast), **or** Go 1.22+ to build binaries
- Persistent disk for the data volume (`vault.db`, `unseal.key`, `root.token`)
- For public HTTPS: a DNS name, ports 80/443 forwarded, Cloudflare (or similar) on **DNS only**

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

Host port **8200** maps to container **8080**.

## First boot (empty volume)

Passphrase must be **at least 12 characters**.

```bash
export AGENT_VAULT_PASSPHRASE='choose-a-strong-passphrase'
export AGENT_VAULT_INIT=1

docker compose -f deploy/docker-compose.yml up --build -d
```

What happens:

1. Server creates `/data/vault.db`, writes `/data/unseal.key` (mode `0600`), mints a root **admin** token.
2. Root token is written to `/data/root.token` (mode `0600`) — **not** printed in container logs on current builds.
3. Copy the token out once, store it somewhere safe, then delete `root.token` from the volume if you like.

```bash
docker compose -f deploy/docker-compose.yml exec agent-vault cat /data/root.token
```

Then for every future restart:

```bash
unset AGENT_VAULT_INIT
unset AGENT_VAULT_PASSPHRASE   # not needed after init; remove from env
docker compose -f deploy/docker-compose.yml up -d
```

Health:

```bash
curl -s http://localhost:8200/health
# {"ok":true}
```

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

Do **not** give every agent the root token.

```bash
export AGENT_VAULT_URL=http://beast:8200
export AGENT_VAULT_TOKEN=<admin-token>

vault token create --label cursor-cloud --scope agent
vault token create --label cicd --scope agent
vault token list
```

Save each returned `avt_…` value in that agent’s secret store / MCP env. Revoke with:

```bash
vault token revoke --id <token-id-from-list>
```

## HTTPS for cloud agents (optional)

Goal: cloud agents reach `https://vault.example.com` while LAN `http://beast:8200` still works.

1. Open Admin UI → **Settings → Network & HTTPS**.
2. Set public hostname (FQDN only, e.g. `vault.example.com`).
3. In Cloudflare DNS: **A/AAAA** → beast public IP, proxy **DNS only** (grey cloud).
4. Forward host ports **80** and **443**.
5. Wait for public DNS.
6. Enable HTTPS, save (vault writes `Caddyfile` into the shared volume).
7. Start the profile:

```bash
docker compose -f deploy/docker-compose.yml --profile https up -d
```

Set `AGENT_VAULT_TRUST_PROXY=1` on the vault service when Caddy sits in front, so rate limits and IP allowlist see the real client IP from `X-Forwarded-For`.

Agents then use:

```bash
export AGENT_VAULT_URL=https://vault.example.com
export AGENT_VAULT_TOKEN=<agent-token>
```

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
| `AGENT_VAULT_URL` | `http://localhost:8200` | Client base URL (CLI/MCP) |
| `AGENT_VAULT_TOKEN` | — | Client bearer token |

## Passphrase & master rotation

```bash
# Rewrap master under a new passphrase (tokens revoked; new root returned once)
vault change-passphrase --old 'current-passphrase' --new 'replacement-passphrase'

# New master key + rewrite unseal.key + rewrap all secrets (tokens revoked)
vault rotate-master --passphrase 'current-passphrase'
```

Both are also available under **Settings → Security** in the Admin UI. After either operation, update admin/agent tokens everywhere.

## Smoke checks

From a clone of this repo:

```bash
bash scripts/smoke.sh
bash scripts/smoke-ui.sh
bash scripts/smoke-backup.sh
bash scripts/smoke-settings.sh
```

## Upgrading

1. Pull / rebuild the image.
2. `docker compose -f deploy/docker-compose.yml up -d --build`
3. SQLite migrations (e.g. token `scope` column) run automatically on open.
4. Remint agent tokens only if you rotated passphrase/master or revoked tokens.
