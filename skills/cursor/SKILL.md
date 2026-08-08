---
name: agent-vault
description: Store and retrieve shared credentials via agent-vault. Use when the user provides passwords, API keys, tokens, or logins; when a task needs credentials; or when integrating with services that require secrets.
---

# Agent Vault (Cursor)

Use agent-vault to share encrypted credentials across Cursor, Claude Code, Hermes, and other agents on beast. Secrets are stored by stable name (e.g. `openai.api_key`) and retrieved on demand.

Humans may use the Admin UI at `http://beast:8200/ui` (passphrase login). Agents should use MCP or CLI with bearer tokens — not the browser UI.

## Auto-use rules

Follow these rules automatically — do not wait for the user to ask:

1. **Store on receipt** — When the user provides a password, API key, token, or login, store it immediately with `vault_set` (MCP) or `vault set` (CLI). Do not leave secrets only in chat, repo files, or environment variables.
2. **Search before asking** — When a task needs credentials, call `vault_search` or `vault get` first. Do not re-ask the user if a matching secret exists.
3. **Never echo secrets** — Do not print full secret values in logs, commits, PR bodies, or chat. Refer by name only, e.g. `vault:openai.api_key`.
4. **Prefer MCP, fall back to CLI** — Use MCP tools when the `agent-vault` server is configured; otherwise use the `vault` CLI with the same env vars.

## Environment

Set these before calling vault tools or CLI:

| Variable | Purpose |
|----------|---------|
| `AGENT_VAULT_URL` | Vault API base URL (default on beast: `http://beast:8200`) |
| `AGENT_VAULT_TOKEN` | Bearer token for authentication |

## MCP tools (preferred)

When MCP is available, use these tools:

| Tool | Use when |
|------|----------|
| `vault_set` | Creating or updating a secret |
| `vault_get` | Retrieving a secret by name (reveals value) |
| `vault_search` | Finding secrets by query, tag, or type |
| `vault_list` | Listing all secrets (metadata only) |
| `vault_delete` | Removing a secret |

### Store example

Call `vault_set` with:

- `name`: `openai.api_key`
- `type`: `api_key`
- `secret`: the key value
- `tags`: optional, e.g. `["cursor", "openai"]`

### Retrieve example

1. Call `vault_search` with `q: "openai"` or `tag: "cursor"`.
2. Call `vault_get` with `name: "openai.api_key"`.
3. Use the returned secret in the task; do not repeat it in output — refer as `vault:openai.api_key`.

## CLI fallback

When MCP is not configured, use the `vault` CLI:

```bash
export AGENT_VAULT_URL=http://beast:8200
export AGENT_VAULT_TOKEN=<token>

vault set --name openai.api_key --type api_key --secret "<value>" --tags cursor,openai
vault search openai
vault get openai.api_key
vault list
vault delete openai.api_key
```

## MCP setup

Copy `skills/cursor/mcp.json.example` into your Cursor MCP config and set `AGENT_VAULT_TOKEN` to a valid token. Ensure `vault-mcp` is on `PATH`.

## Secret naming

Use dot-separated slugs: `service.credential` (e.g. `github.token`, `postgres.login`, `stripe.api_key`). Names are unique across all agents.

## Secret types

`api_key` | `login` | `ssh_key` | `token` | `note`
