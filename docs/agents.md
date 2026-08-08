# Using Agent Vault from any agent

Agent Vault is **not** locked to Cursor, Claude Code, or Hermes. Any process that can speak **HTTP**, run a **CLI**, or launch an **MCP stdio** server can use it.

This page is the integration guide for AI agents, automation bots, CI jobs, and IDE plugins. If you are the human setting this up, mint an **agent**-scoped token first ([install guide](install-and-ops.md)), then hand the agent this page or [`skills/SKILL.md`](../skills/SKILL.md).

## Pick an integration path

| Path | When to use | What you need |
|------|-------------|----------------|
| **MCP** (`vault-mcp`) | Host supports Model Context Protocol tools | Binary + env + MCP config |
| **CLI** (`vault`) | Shell tools, SSH agents, simple scripts | Binary on `PATH` + env |
| **REST** (`/v1`) | Custom agent runtimes, other languages | HTTP client + bearer token |

All three use the same auth: `AGENT_VAULT_URL` + `AGENT_VAULT_TOKEN`.

## Universal rules (every agent)

Copy these into your agent’s system prompt or skill file (canonical copy: [`skills/SKILL.md`](../skills/SKILL.md)):

1. **Store on receipt** — When the user pastes a password, API key, token, or login, store it immediately. Do not leave it only in chat or a repo file.
2. **Search before asking** — Before asking the user for credentials, search the vault.
3. **Never echo secrets** — Do not print full secret values in logs, commits, PRs, or chat. Refer by name: `vault:openai.api_key`.
4. **Prefer least privilege** — Use an **agent**-scoped token. Do not use the root admin token for routine work.
5. **Humans own Settings** — Hostname, HTTPS, passphrase change, master rotate, and backups are operator tasks. Agents should not run backup/restore unless explicitly asked and given an admin token.

## 1) MCP (recommended when available)

`vault-mcp` is a stdio MCP server that exposes:

| Tool | Purpose |
|------|---------|
| `vault_set` | Create or update |
| `vault_get` | Reveal by name |
| `vault_search` | Query / tag / type |
| `vault_list` | Metadata list |
| `vault_delete` | Delete by name |

### Generic stdio config

See [`skills/mcp.stdio.json.example`](../skills/mcp.stdio.json.example):

```json
{
  "mcpServers": {
    "agent-vault": {
      "command": "vault-mcp",
      "env": {
        "AGENT_VAULT_URL": "http://localhost:8200",
        "AGENT_VAULT_TOKEN": "<agent-scoped-token>"
      }
    }
  }
}
```

Adapt the JSON shape to your host:

| Host | Typical config location / shape |
|------|----------------------------------|
| Cursor | MCP settings JSON (`mcpServers`) — see `skills/cursor/mcp.json.example` |
| Claude Code / Claude Desktop | MCP server entry with `command` + `env` |
| Windsurf / Cascade | MCP servers config (stdio command) |
| Continue / Cline / Roo | MCP or tools config supporting stdio servers |
| Custom orchestrator | Spawn `vault-mcp` as stdio MCP and register tools |

If your product uses a different key than `mcpServers`, keep `command: vault-mcp` and the two env vars—the protocol is the same.

### Tool argument cheat sheet

**vault_set**

```json
{
  "name": "openai.api_key",
  "type": "api_key",
  "secret": "sk-…",
  "tags": ["openai"],
  "username": "",
  "url": "",
  "notes": ""
}
```

**vault_get** — `{ "name": "openai.api_key" }`  
**vault_search** — `{ "q": "openai" }` or `{ "tag": "ci" }` or `{ "type": "api_key" }`  
**vault_list** — `{}`  
**vault_delete** — `{ "name": "openai.api_key" }`

## 2) CLI

Install `vault` on the agent’s machine (or mount the Docker image binary). Ensure it is on `PATH`.

```bash
export AGENT_VAULT_URL=http://localhost:8200   # or https://vault.example.com
export AGENT_VAULT_TOKEN=avt_…

vault search openai
vault get openai.api_key
vault set --name openai.api_key --type api_key --secret "$VALUE" --tags agents
vault list
vault delete openai.api_key
```

Full flag reference: [CLI](cli.md).

This path works for agents that only have a shell tool (many “computer use” / SSH / terminal agents).

## 3) Raw REST

Any language works. Minimal Python example:

```python
import os, requests

base = os.environ["AGENT_VAULT_URL"].rstrip("/")
tok = os.environ["AGENT_VAULT_TOKEN"]
h = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

# search
r = requests.get(f"{base}/v1/search", params={"q": "openai"}, headers=h, timeout=30)
r.raise_for_status()
print(r.json())  # metadata only

# reveal
r = requests.get(f"{base}/v1/secrets/openai.api_key", params={"reveal": "1"}, headers=h, timeout=30)
r.raise_for_status()
secret = r.json()["secret"]
# use secret; do not log it
```

Full route list: [API](api.md).

## Minting a token for a new agent

Operator (admin token) once:

```bash
export AGENT_VAULT_URL=http://localhost:8200
export AGENT_VAULT_TOKEN=<admin-token>

vault token create --label <agent-name> --scope agent
# → save the avt_… value into that agent’s env / MCP config only
```

One token per agent (or per environment). Revoke when the agent is retired:

```bash
vault token list
vault token revoke --id <id>
```

## Naming conventions agents should follow

- Prefer `service.credential`: `stripe.api_key`, `github.token`, `aws.access_key`.
- Add tags for the consuming agent or environment: `["cursor","prod"]`.
- Types: `api_key` | `login` | `ssh_key` | `token` | `note`.

## Cloud / remote agents

1. Operator enables HTTPS in Settings (see [Install](install-and-ops.md)).
2. Agent uses `AGENT_VAULT_URL=https://vault.example.com` (or `https://<hostname>`).
3. Prefer agent-scoped tokens. IP allowlist is **optional and empty by default** (all IPs allowed)—only add egress IPs if the operator chooses to restrict access.

## What agents should not do

- Browse `/ui` or scrape the Admin UI
- Call backup/export/rotate endpoints with an agent token (they will get `403`—and should not have admin tokens for routine work)
- Persist revealed secrets into git, issue trackers, or long-lived logs
- Share one token across many untrusted tenants

## Drop-in skill file

Point any skill-capable agent at:

**[`skills/SKILL.md`](../skills/SKILL.md)**

Product-specific stubs under `skills/cursor`, `skills/claude`, and `skills/hermes` only add host tips; the behavior rules are the same for every agent.
