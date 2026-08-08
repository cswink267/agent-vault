---
name: agent-vault
description: Store and retrieve shared credentials via agent-vault. Use when the user provides passwords, API keys, tokens, or logins; when a task needs credentials; or when integrating with services that require secrets.
---

# Agent Vault (Claude Code / Claude Desktop)

Follow the **universal** skill and docs—behavior is the same for every agent:

→ **[`../SKILL.md`](../SKILL.md)**  
→ **[`../../docs/agents.md`](../../docs/agents.md)**

## Claude-specific setup

1. Install `vault` and `vault-mcp` (or use the Docker image binaries).
2. Register `vault-mcp` as a stdio MCP server with:

   - `AGENT_VAULT_URL` — e.g. `http://localhost:8200` or `https://<hostname>`
   - `AGENT_VAULT_TOKEN` — agent-scoped token

   Shape reference: [`../mcp.stdio.json.example`](../mcp.stdio.json.example) (adapt to Claude’s MCP config format).

3. Prefer MCP tools; use the `vault` CLI in Bash when MCP is not wired.
