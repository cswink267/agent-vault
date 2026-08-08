---
name: agent-vault
description: Store and retrieve shared credentials via agent-vault. Use when the user provides passwords, API keys, tokens, or logins; when a task needs credentials; or when integrating with services that require secrets.
---

# Agent Vault (Claude Code)

Use agent-vault to share encrypted credentials across Claude Code, Cursor, Hermes, and other agents on beast. Secrets are stored by stable name (e.g. `openai.api_key`) and retrieved on demand.

## Auto-use rules

Follow these rules automatically — do not wait for the user to ask:

1. **Store on receipt** — When the user provides a password, API key, token, or login, store it immediately with `vault_set` (MCP) or `vault set` (CLI). Do not leave secrets only in chat, repo files, or environment variables.
2. **Search before asking** — When a task needs credentials, call `vault_search` or `vault get` first. Do not re-ask the user if a matching secret exists.
3. **Never echo secrets** — Do not print full secret values in logs, commits, PR bodies, or chat. Refer by name only, e.g. `vault:openai.api_key`.
4. **Prefer MCP, fall back to CLI** — Use MCP tools when available; otherwise use the `vault` CLI with the same env vars.

## Environment

| Variable | Purpose |
|----------|---------|
| `AGENT_VAULT_URL` | Vault API base URL (default on beast: `http://beast:8200`) |
| `AGENT_VAULT_TOKEN` | Bearer token for authentication |

Export before shell commands:

```bash
export AGENT_VAULT_URL=http://beast:8200
export AGENT_VAULT_TOKEN=<token>
```

## MCP tools

Claude Code can use MCP when configured with the `vault-mcp` server. Available tools:

| Tool | Use when |
|------|----------|
| `vault_set` | Creating or updating a secret |
| `vault_get` | Retrieving a secret by name (reveals value) |
| `vault_search` | Finding secrets by query, tag, or type |
| `vault_list` | Listing all secrets (metadata only) |
| `vault_delete` | Removing a secret |

### Store via MCP

Call `vault_set` with `name`, `type`, and `secret`. Example: store an OpenAI key as `openai.api_key` with type `api_key`.

### Retrieve via MCP

1. Call `vault_search` to find matching secrets.
2. Call `vault_get` with the secret name.
3. Use the value in the task; refer externally as `vault:openai.api_key`.

## CLI

When MCP is not available, use the `vault` CLI:

```bash
vault set --name openai.api_key --type api_key --secret "<value>" --tags claude,openai
vault search openai
vault get openai.api_key
vault list
vault delete openai.api_key
```

Other commands: `vault unlock`, `vault lock`, `vault audit`, `vault token create --label claude`.

## Setup

1. Install the `vault` and `vault-mcp` binaries from the agent-vault repo.
2. Set `AGENT_VAULT_URL` and `AGENT_VAULT_TOKEN` in your environment or Claude Code MCP config.
3. For MCP, configure `vault-mcp` as a stdio server with the same env vars (see `skills/cursor/mcp.json.example`).

## Secret naming

Use dot-separated slugs: `service.credential` (e.g. `github.token`, `postgres.login`). Names are unique across all agents.

## Secret types

`api_key` | `login` | `ssh_key` | `token` | `note`
