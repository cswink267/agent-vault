---
name: agent-vault
description: Store and retrieve shared credentials via agent-vault. Use when the user provides passwords, API keys, tokens, or logins; when a task needs credentials; or when integrating with services that require secrets.
---

# Agent Vault (Hermes)

Follow the **universal** skill and docs—behavior is the same for every agent:

→ **[`../SKILL.md`](../SKILL.md)**  
→ **[`../../docs/agents.md`](../../docs/agents.md)**

## Hermes-specific notes

Hermes often has a shell but no MCP host. **Prefer the CLI:**

```bash
export AGENT_VAULT_URL=http://beast:8200
export AGENT_VAULT_TOKEN=<agent-scoped-token>

vault search <query>
vault get <name>
vault set --name <name> --type <type> --secret "<value>" --tags hermes
```

If MCP becomes available, use `vault-mcp` with the same env vars ([`../mcp.stdio.json.example`](../mcp.stdio.json.example)).
