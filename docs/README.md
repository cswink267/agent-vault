# Agent Vault documentation

Agent Vault is a shared, encrypted secrets store for **you** and your **AI agents**. One vault runs on your server. Humans use the browser or CLI; agents use MCP, CLI, or REST.

These guides are written for people who operate the vault day to day. Design history and implementation notes live under [`superpowers/`](superpowers/) — you can ignore those unless you are changing the product.

**License:** [Apache License 2.0](../LICENSE) — Copyright 2026 Chris Swink ([NOTICE](../NOTICE)).

## If you only read two pages

1. **[Install & operations](install-and-ops.md)** — get it running, keep it running, HTTPS, upgrades, troubleshooting  
2. **[Admin UI](admin-ui.md)** — how to use Settings, backups, and secrets in the browser  

Then skim **[Concepts](concepts.md)** so passphrase / `unseal.key` / tokens make sense before you rotate anything.

## Full guide list

| Guide | Who it’s for | What you’ll learn |
|-------|--------------|-------------------|
| [Concepts](concepts.md) | Everyone | Encryption, seal/unseal, tokens, scopes, naming |
| [Install & operations](install-and-ops.md) | Operators | Docker, first boot, HTTPS, env migration/hydrate, upgrades, troubleshooting |
| [Admin UI](admin-ui.md) | Humans | Browser login, Settings, snapshots/exports from the UI |
| [CLI](cli.md) | Humans & agents | Every `vault` command with examples |
| [HTTP API](api.md) | Integrators & agents | Every `/v1` route with curl |
| [Agents](agents.md) | Any AI agent | MCP, CLI, or REST — not tied to one product |
| [Security & backup](security-and-backup.md) | Operators | Threat model, snapshots vs exports, hardening checklist |

## Defaults worth knowing

- **All client IPs are allowed** until you set an IP allowlist yourself in Settings. Empty allowlist = open to anyone who can reach the port.
- Passphrases (vault, snapshot, export) must be **at least 12 characters**.
- New tokens default to **agent** scope (secrets only). The init root token is **admin**.
- Host port **8200** maps to the container’s **8080**.

## In the Admin UI

When the vault is running, the same guides are available under **Docs** in the top nav (`/ui/docs`) after you log in.

## Quick links

| What | Where |
|------|--------|
| Health | `GET http://localhost:8200/health` → `{"ok":true}` |
| Admin UI | `http://localhost:8200/ui` (or `http://<hostname>:8200/ui`) |
| Docs (in UI) | `http://localhost:8200/ui/docs` |
| Mint an agent token | `vault token create --label my-agent --scope agent` |
| Universal agent skill | [`../skills/SKILL.md`](../skills/SKILL.md) |
| MCP stdio example | [`../skills/mcp.stdio.json.example`](../skills/mcp.stdio.json.example) |
| Hydrate scrubbed `.env` from vault | [`../scripts/vault-hydrate`](../scripts/vault-hydrate) + [`env.map.example`](../scripts/examples/env.map.example) |
