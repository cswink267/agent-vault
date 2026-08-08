---
name: agent-vault
description: Store and retrieve shared credentials via agent-vault. Use when the user provides passwords, API keys, tokens, or logins; when a task needs credentials; or when integrating with services that require secrets. Works with any agent that has MCP, a shell (CLI), or HTTP.
---

# Agent Vault (universal)

Use **agent-vault** to share encrypted credentials across **any** AI agent, IDE, or automation—not only Cursor, Claude, or Hermes. Secrets are stored by stable name (e.g. `openai.api_key`) and retrieved on demand.

Humans configure the vault in **Settings** (`/ui/settings`: passphrase login; HTTPS, allowlist, rotate, backups). Agents use **MCP**, **CLI**, or **REST** with a bearer token—not the browser UI.

Full docs: [`docs/agents.md`](../docs/agents.md) · [`docs/cli.md`](../docs/cli.md) · [`docs/api.md`](../docs/api.md)

## Auto-use rules

Follow automatically—do not wait for the user to ask:

1. **Store on receipt** — When the user provides a password, API key, token, or login, store it immediately (`vault_set` / `vault set` / `POST /v1/secrets`). Do not leave secrets only in chat, repo files, or long-lived env dumps.
2. **Search before asking** — When a task needs credentials, search/list first. Do not re-ask if a match exists.
3. **Never echo secrets** — Do not print full secret values in logs, commits, PR bodies, or chat. Refer by name: `vault:openai.api_key`.
4. **Least privilege** — Prefer an **agent**-scoped token. Do not use admin/root tokens for routine secret get/set.
5. **Interface order** — Prefer MCP tools when configured; else CLI; else REST. Same env vars for all.

## Environment

| Variable | Purpose |
|----------|---------|
| `AGENT_VAULT_URL` | API base. Example: `http://localhost:8200` or `http://<hostname>:8200`. Cloud: `https://<public_hostname>` when HTTPS is enabled. |
| `AGENT_VAULT_TOKEN` | Bearer token (`avt_…`), preferably scope `agent` |

## MCP tools

| Tool | Use when |
|------|----------|
| `vault_set` | Create or update |
| `vault_get` | Retrieve by name (reveals value) |
| `vault_search` | Find by query, tag, or type |
| `vault_list` | List metadata |
| `vault_delete` | Remove |

Setup: run `vault-mcp` as a stdio MCP server with the env above. Generic example: [`mcp.stdio.json.example`](mcp.stdio.json.example). Adapt the JSON wrapper to your host (Cursor, Claude, Windsurf, Continue, custom orchestrators, etc.).

### Store

`vault_set` with `name`, `type`, `secret`, optional `tags` / `username` / `url` / `notes`.

### Retrieve

1. `vault_search` (e.g. `q: "openai"`)
2. `vault_get` with the name
3. Use the value in-process; externally refer as `vault:openai.api_key`

## CLI fallback

```bash
export AGENT_VAULT_URL=http://localhost:8200
export AGENT_VAULT_TOKEN=<token>

vault set --name openai.api_key --type api_key --secret "<value>" --tags agents,openai
vault search openai
vault get openai.api_key
vault list
vault delete openai.api_key
```

## REST fallback

```bash
curl -sS -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  "$AGENT_VAULT_URL/v1/search?q=openai"

curl -sS -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  "$AGENT_VAULT_URL/v1/secrets/openai.api_key?reveal=1"
```

## Naming & types

- Names: `service.credential` (`github.token`, `postgres.login`)
- Types: `api_key` | `login` | `ssh_key` | `token` | `note`

## Local `.env` files

If credentials still live in dotenv files: store them in the vault, scrub the file, prefer MCP/CLI at use time. Operators who must refill a classic `.env` for process startup can use `scripts/vault-hydrate` with a non-secret `KEY=vault.name` map (see `docs/install-and-ops.md`).

## Out of scope for agents

Do not run backup, restore, export, import, change-passphrase, or rotate-master unless the user explicitly asks **and** you have an admin token. Those are operator workflows.
