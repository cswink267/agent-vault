# agent-vault

Shared **encrypted secrets vault** for humans and AI agents. One service on your host; clients use REST, CLI, MCP, or the Admin UI.

Works with **any** agent that can call HTTP, run a shell, or speak MCP—not only Cursor, Claude Code, or Hermes.

## Documentation

Start here: **[docs/README.md](docs/README.md)**

| Guide | Contents |
|-------|----------|
| [Concepts](docs/concepts.md) | Encryption, seal/unseal, tokens & scopes |
| [Install & ops](docs/install-and-ops.md) | Docker, first boot, HTTPS, allowlist, upgrades |
| [Admin UI](docs/admin-ui.md) | Browser operator guide (`/ui`, `/ui/docs`) |
| [CLI](docs/cli.md) | Full `vault` reference |
| [HTTP API](docs/api.md) | Every `/v1` route with curl |
| [Agents](docs/agents.md) | MCP / CLI / REST for any agent |
| [Security & backup](docs/security-and-backup.md) | Snapshots vs exports, hardening |

**Agent skill (universal):** [`skills/SKILL.md`](skills/SKILL.md)  
**MCP stdio example:** [`skills/mcp.stdio.json.example`](skills/mcp.stdio.json.example)

## 60-second quickstart

```bash
export AGENT_VAULT_PASSPHRASE='choose-a-strong-passphrase'  # ≥ 12 chars
export AGENT_VAULT_INIT=1
docker compose -f deploy/docker-compose.yml up --build -d

# Read root token once from the volume, then unset INIT/PASSPHRASE for next boots
docker compose -f deploy/docker-compose.yml exec agent-vault cat /data/root.token
```

```bash
export AGENT_VAULT_URL=http://localhost:8200   # or http://<hostname>:8200
export AGENT_VAULT_TOKEN=<root-token>

# Prefer a dedicated agent token:
vault token create --label my-agent --scope agent

vault set --name openai.api_key --type api_key --secret 'sk-…' --tags agents
vault search openai
vault get openai.api_key
```

- Admin UI: `http://localhost:8200/ui` (passphrase login)
- Health: `curl -s http://localhost:8200/health` → `{"ok":true}`

## Interfaces

| Interface | Who | Auth |
|-----------|-----|------|
| Admin UI `/ui` | Humans | Passphrase session |
| REST `/v1` | Any client | Bearer token |
| CLI `vault` | Humans & agents | `AGENT_VAULT_URL` + `AGENT_VAULT_TOKEN` |
| MCP `vault-mcp` | MCP-capable agents | Same env as CLI |

Token scopes: **admin** (full) vs **agent** (secrets only). See [concepts](docs/concepts.md).

## Build from source

```bash
docker build -t agent-vault:local .
# or
go build -o bin/vault-server ./cmd/vault-server
go build -o bin/vault ./cmd/vault
go build -o bin/vault-mcp ./cmd/vault-mcp
```

Compose: `deploy/docker-compose.yml` (canonical) or root `docker-compose.yml`. Host **8200** → container **8080**.

Optional public HTTPS: Settings → hostname + Cloudflare **DNS only** (grey cloud), then `docker compose --profile https up -d`. Details in [install & ops](docs/install-and-ops.md).

## License / status

Internal operator tooling for a single-tenant host deployment. Design history under [`docs/superpowers/`](docs/superpowers/).
