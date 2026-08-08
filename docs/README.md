# Agent Vault documentation

Agent Vault is a shared, encrypted secrets store for humans and AI agents. One vault on your host (typically **beast**); many clients over REST, CLI, MCP, or the Admin UI.

## Read in this order

| Guide | Audience | What you’ll learn |
|-------|----------|-------------------|
| [Concepts](concepts.md) | Everyone | Encryption, seal/unseal, tokens, scopes, naming |
| [Install & operations](install-and-ops.md) | Operators | Docker, first boot, HTTPS, day-2 ops |
| [Admin UI](admin-ui.md) | Humans | Browser login, Settings, backups from the UI |
| [CLI](cli.md) | Humans & agents | Full `vault` command reference |
| [HTTP API](api.md) | Integrators & agents | Every `/v1` route with curl examples |
| [Agents](agents.md) | Any AI agent | MCP, CLI, or raw REST — not tied to one product |
| [Security & backup](security-and-backup.md) | Operators | Threat model, snapshots, exports, hardening |

Design history and implementation plans live under [`superpowers/`](superpowers/) (internal specs; not required for day-to-day use).

## Quick links

- Health: `GET http://localhost:8200/health`
- Admin UI: `http://localhost:8200/ui` (or `http://beast:8200/ui`)
- Mint an agent token: `vault token create --label my-agent --scope agent`
- Universal agent skill: [`../skills/SKILL.md`](../skills/SKILL.md)
- Generic MCP stdio config: [`../skills/mcp.stdio.json.example`](../skills/mcp.stdio.json.example)
