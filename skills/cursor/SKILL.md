---
name: agent-vault
description: Store and retrieve shared credentials via agent-vault. Use when the user provides passwords, API keys, tokens, or logins; when a task needs credentials; or when integrating with services that require secrets.
---

# Agent Vault (Cursor)

Follow the **universal** skill and docs—behavior is the same for every agent:

→ **[`../SKILL.md`](../SKILL.md)**  
→ **[`../../docs/agents.md`](../../docs/agents.md)**

## Cursor-specific setup

1. Copy [`mcp.json.example`](mcp.json.example) into your Cursor MCP config (or merge the `agent-vault` server block).
2. Set `AGENT_VAULT_TOKEN` to an **agent**-scoped token (`vault token create --label cursor --scope agent`).
3. Ensure `vault-mcp` is on `PATH` (Docker image: `/usr/local/bin/vault-mcp`).
4. Prefer MCP tools; fall back to the `vault` CLI in the terminal if MCP is unavailable.

Example URL: `http://localhost:8200`. For cloud agents, use `https://<hostname>` after HTTPS is enabled in Settings.
