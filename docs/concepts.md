# Concepts

This page explains how Agent Vault works under the hood—enough to operate it safely without reading the Go source.

## What it is

Agent Vault stores **named secrets** (API keys, logins, tokens, SSH keys, notes) in an encrypted SQLite database. Clients authenticate with a **bearer token**. Humans can also use a browser **Admin UI** with the vault passphrase.

Typical layout:

```text
You (browser)  ──passphrase──►  /ui
Agents / CLI   ──Bearer token─►  /v1
MCP wrapper    ──same token───►  /v1  (via vault-mcp)
```

## Encryption model

1. At init, the vault generates a random **master key** (256-bit).
2. Every secret value is encrypted with AES-256-GCM under a per-secret data key; that key is wrapped under the master key.
3. The master key itself is wrapped under a key derived from your **passphrase** (Argon2id).
4. The same master key is also written (hex) to **`unseal.key`** on disk so the server can auto-unseal after reboot without typing the passphrase.

So:

| Material | Role |
|----------|------|
| Passphrase | Human unlock / UI login / change-passphrase |
| `unseal.key` | Auto-unseal and disaster recovery (treat as the master key) |
| Bearer tokens | API/CLI/MCP auth (hashed at rest; plaintext shown once) |

Changing the passphrase **rewraps** the master key; it does **not** rewrite `unseal.key` or re-encrypt secrets. Rotating the master key (`rotate-master`) does both: new master, rewrap all secrets, rewrite `unseal.key`, revoke all tokens.

## Sealed vs unsealed

- **Unsealed** — master key in memory; secret create/read/update/delete and export work.
- **Sealed** — master key wiped from memory; most secret operations fail until unlock or auto-unseal.

On Docker, if `unseal.key` is present, the server usually auto-unseals at start. Operators can still `vault lock` / `vault unlock`.

## Tokens and scopes

Tokens look like `avt_<hex>`. Only the SHA-256 hash is stored.

| Scope | Can do |
|-------|--------|
| **admin** | Everything: secrets, tokens, backups, lock, passphrase/master rotate, audit |
| **agent** | Secrets only: list, get (reveal), create/update, search, delete. No backups, no token minting, no rotate |

- The init **root** token is `admin`.
- New tokens default to **agent** (`vault token create --label …`).
- You cannot revoke the **last** admin token.
- Change-passphrase and rotate-master **revoke all tokens** and mint a fresh root admin token once.

Give each agent its own labeled agent-scoped token. Prefer that over sharing the root token.

## Secret names and types

- **Names** are unique slugs. Convention: `service.credential` — e.g. `openai.api_key`, `github.token`, `postgres.login`.
- **Types**: `api_key` | `login` | `ssh_key` | `token` | `note`
- Optional fields: `username`, `url`, `tags`, `notes`, `metadata`

Listing and searching return **metadata** without the secret value. Revealing requires an explicit get (`vault get` or `GET /v1/secrets/{name}?reveal=1`).

## Three ways to talk to the vault

| Interface | Best for | Auth |
|-----------|----------|------|
| **Admin UI** (`/ui`) | Humans: browse, Settings, downloads | Passphrase → session cookie + CSRF |
| **CLI** (`vault`) | Scripts, SSH sessions, agents without MCP | `AGENT_VAULT_TOKEN` |
| **REST** (`/v1`) | Any language or agent that can HTTP | `Authorization: Bearer …` |
| **MCP** (`vault-mcp`) | Agents that speak Model Context Protocol | Same env as CLI; tools wrap REST |

MCP does not invent a new security model—it is a thin tool layer over `/v1`.

## Network shapes

1. **Private LAN** — `http://beast:8200` (or localhost). Fine for trusted networks.
2. **Public HTTPS** — optional Compose `https` profile (Caddy + Let’s Encrypt). Configure hostname in Settings; Cloudflare DNS must be **grey cloud** (DNS only) for HTTP-01.
3. **IP allowlist** — optional; when set, non-listed clients get `403` on `/ui` and `/v1`. `/health` always stays open.

## Mental model for agents

1. Search or list before asking the human for credentials.
2. Store secrets as soon as the human provides them.
3. Never paste full secret values into chat, commits, or logs—refer by name (`vault:openai.api_key`).
4. Use an **agent**-scoped token, not the root admin token, unless the task truly needs admin operations.
