---
name: agent-vault
description: Store and retrieve shared credentials via agent-vault. Use when the user provides passwords, API keys, tokens, or logins; when a task needs credentials; or when integrating with services that require secrets.
---

# Agent Vault (Hermes)

Use agent-vault to share encrypted credentials across Hermes, Cursor, Claude Code, and other agents on beast. Secrets are stored by stable name (e.g. `openai.api_key`) and retrieved on demand.

Humans configure the vault in **Settings** at `http://beast:8200/ui/settings` (passphrase login; hostname/HTTPS, change passphrase, rotate master, backup downloads). Agents should use MCP or CLI with bearer tokens — not the browser UI. For disaster recovery, operators use `vault backup` / `restore` / `export` / `import` (CLI); agents do not run backup commands.

## Auto-use rules

Follow these rules automatically — do not wait for the user to ask:

1. **Store on receipt** — When the user provides a password, API key, token, or login, store it immediately with `vault set` (CLI) or `vault_set` (MCP if available). Do not leave secrets only in chat, repo files, or environment variables.
2. **Search before asking** — When a task needs credentials, run `vault search` or `vault get` first. Do not re-ask the user if a matching secret exists.
3. **Never echo secrets** — Do not print full secret values in logs, commits, PR bodies, or chat. Refer by name only, e.g. `vault:openai.api_key`.
4. **CLI first** — Hermes typically has no MCP server. Use the `vault` CLI as the primary interface. If MCP tools are available, prefer them; otherwise always fall back to CLI.

## Environment

Set before every vault command:

```bash
export AGENT_VAULT_URL=http://beast:8200   # or https://<public_hostname> when HTTPS is enabled
export AGENT_VAULT_TOKEN=<token>
```

| Variable | Purpose |
|----------|---------|
| `AGENT_VAULT_URL` | Vault API base URL. Default on beast (private LAN): `http://beast:8200`. When HTTPS is configured in Settings, use `https://<public_hostname>` for remote/cloud agents. |
| `AGENT_VAULT_TOKEN` | Bearer token for authentication |

## CLI commands (primary)

| Command | Use when |
|---------|----------|
| `vault set` | Creating or updating a secret |
| `vault get` | Retrieving a secret by name (reveals value) |
| `vault search` | Finding secrets by query, tag, or type |
| `vault list` | Listing all secrets (metadata only) |
| `vault delete` | Removing a secret |

### Store example

```bash
vault set --name openai.api_key --type api_key --secret "<value>" --tags hermes,openai
```

### Retrieve example

```bash
vault search openai
vault get openai.api_key
```

Use the returned secret in the task; refer externally as `vault:openai.api_key` — never repeat the full value in output.

## MCP fallback (optional)

If MCP is configured with `vault-mcp`, these tools are equivalent to CLI commands:

- `vault_set`, `vault_get`, `vault_search`, `vault_list`, `vault_delete`

Prefer MCP when present; otherwise use CLI commands above.

## Setup

1. Install the `vault` binary from the agent-vault repo and ensure it is on `PATH`.
2. Export `AGENT_VAULT_URL` and `AGENT_VAULT_TOKEN` in your shell profile or task environment.
3. Verify connectivity: `vault list` (requires an unsealed vault).

## Secret naming

Use dot-separated slugs: `service.credential` (e.g. `github.token`, `postgres.login`). Names are unique across all agents.

## Secret types

`api_key` | `login` | `ssh_key` | `token` | `note`
