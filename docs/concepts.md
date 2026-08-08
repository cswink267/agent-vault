# Concepts

How Agent Vault works—enough to operate it safely without reading the Go source.

## What it is

Agent Vault stores **named secrets** (API keys, logins, tokens, SSH keys, notes) in an encrypted SQLite database.

- **Humans** open the Admin UI with the vault **passphrase**, or use the CLI with a bearer token.
- **Agents** use a bearer token via MCP, CLI, or REST. They should not use the browser UI.

```text
You (browser)  ── passphrase ──►  /ui
Agents / CLI   ── Bearer token ►  /v1
MCP (vault-mcp) ── same token ─►  /v1
```

## Encryption model

1. At init, the vault generates a random **master key** (256-bit).
2. Each secret value is encrypted with AES-256-GCM under a per-secret data key; that data key is wrapped under the master key.
3. The master key is wrapped under a key derived from your **passphrase** (Argon2id).
4. The same master key is also written (hex) to **`unseal.key`** on disk so the server can auto-unseal after reboot without typing the passphrase.

| Material | What it does | Treat it like |
|----------|--------------|---------------|
| Passphrase | UI login, unlock, change-passphrase | Your vault password |
| `unseal.key` | Auto-unseal + disaster recovery | The master key itself |
| Bearer tokens (`avt_…`) | API / CLI / MCP auth | API keys (shown once; hashed at rest) |

**Change passphrase** rewraps the master key under the new passphrase. It does **not** rewrite `unseal.key` or re-encrypt secrets. It **does** revoke all bearer tokens and mint a new root admin token (shown once).

**Rotate master** creates a new master key, rewraps all secrets, rewrites `unseal.key`, and revokes all tokens. Use this if you believe the master key or `unseal.key` was exposed.

## Sealed vs unsealed

| State | Meaning |
|-------|---------|
| **Unsealed** | Master key in memory. You can create, read, update, delete, and export secrets. |
| **Sealed** | Master key wiped from memory. Secret operations fail until unlock (or auto-unseal). |

On Docker, if `unseal.key` is present, the server usually auto-unseals at start. You can still `vault lock` / `vault unlock` (or use Lock / Unlock in the UI).

## Tokens and scopes

Tokens look like `avt_<hex>`. Only a SHA-256 hash is stored in the database. The plaintext is shown **once** when created.

| Scope | Can do |
|-------|--------|
| **admin** | Everything: secrets, tokens, backups, lock, passphrase/master rotate, audit |
| **agent** | Secrets only: list, get (reveal), create/update, search, delete |

Rules that matter in practice:

- The init **root** token is `admin`.
- `vault token create` defaults to **agent** unless you pass `--scope admin`.
- You cannot revoke the **last** admin token (the API returns `409`).
- Change-passphrase and rotate-master **revoke every token** and return a fresh root admin token once.

Give each agent its own labeled **agent**-scoped token. Do not share the root token with routine automation.

## Secret names and types

- **Names** are unique slugs. Convention: `service.credential` — e.g. `openai.api_key`, `github.token`, `postgres.login`.
- **Types**: `api_key` | `login` | `ssh_key` | `token` | `note`
- Optional fields: `username`, `url`, `tags`, `notes`, `metadata`

List and search return **metadata only** (no secret value). Revealing requires an explicit get (`vault get` or `GET /v1/secrets/{name}?reveal=1`).

## Ways to talk to the vault

| Interface | Best for | Auth |
|-----------|----------|------|
| **Admin UI** (`/ui`) | Humans: browse secrets, Settings, downloads | Passphrase → session cookie + CSRF |
| **CLI** (`vault`) | Scripts, SSH sessions, agents without MCP | `AGENT_VAULT_URL` + `AGENT_VAULT_TOKEN` |
| **REST** (`/v1`) | Any language or custom agent | `Authorization: Bearer …` |
| **MCP** (`vault-mcp`) | Agents that speak Model Context Protocol | Same env as CLI; tools wrap REST |

MCP does not invent a new security model—it is a thin tool layer over `/v1`.

## Network shapes

1. **Private network** — `http://localhost:8200` or `http://<hostname>:8200`. Fine on a trusted network.
2. **Public HTTPS** — optional Compose `https` profile (Caddy + Let’s Encrypt). Set the hostname in Settings. If you use Cloudflare, DNS must be **grey cloud** (DNS only) for HTTP-01 certificate issuance.
3. **IP allowlist** — **off by default**. With an empty allowlist, every client IP that can reach the port is allowed. You must enter IPs/CIDRs in Settings yourself if you want to restrict access. When set, non-listed clients get `403` on `/ui` and `/v1`. `/health` always stays open.

## Mental model for agents

1. Search or list before asking the human for credentials.
2. Store secrets as soon as the human provides them.
3. Never paste full secret values into chat, commits, or logs—refer by name (`vault:openai.api_key`).
4. Use an **agent**-scoped token, not the root admin token, unless the task truly needs admin operations.
