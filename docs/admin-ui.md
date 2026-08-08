# Admin UI

The Admin UI is for **humans**. Log in with the vault passphrase in a browser. Agents should use MCP, CLI, or REST with a bearer token—not this UI.

## Open it

| Where you are | URL |
|---------------|-----|
| Same machine as the vault | `http://localhost:8200/ui` |
| Another host on your network | `http://<hostname>:8200/ui` |
| Public HTTPS configured | `https://vault.example.com/ui` |

Log in with the vault **passphrase** (the same one from init / unlock). A successful login also **unseals** the vault if it was sealed.

If login fails repeatedly, wait—attempts are rate-limited on purpose.

## What you can do

### Secrets

On the Secrets page you can:

- List and search stored credentials
- Create, edit, and delete secrets
- Reveal a secret’s value when you need it (those responses are marked non-cacheable)

Use clear names (`openai.api_key`, `github.token`) and tags so agents can find things later.

### Top bar (every page)

- **Lock / Unlock** — seal or unseal without logging out
- Navigation: **Secrets**, **New**, **Audit**, **Settings**, **Docs**
- **Logout** — end the browser session

### Docs (`/ui/docs`)

After login, **Docs** in the top bar opens the same human guides that live in this `docs/` folder (overview, concepts, install, CLI, API, agents, security). Links between guides are rewritten so they stay inside `/ui/docs/…`. Use this when you are already in the Admin UI and do not want to dig through the repo.

### Settings (`/ui/settings`)

This is the operator home. Everything here is intentional—nothing restrictive is turned on until you change it.

#### Network & HTTPS

- **Public hostname** — FQDN only (example: `vault.example.com`). Leave blank if you only use private/LAN access.
- **Enable HTTPS** — writes a Caddyfile when a hostname is set; you still start the Compose `https` profile on the host.
- **Status** — private URL, public URL, Caddyfile state, and the exact apply command when HTTPS is ready.
- **Cloudflare checklist** — grey-cloud (DNS only) steps for certificate issuance.
- **IP allowlist** — **optional and empty by default**. Empty means **all IPs are allowed**. Only fill this in if you want to restrict who can reach `/ui` and `/v1`. `/health` stays open either way.

See [Install & operations](install-and-ops.md) for the Docker allowlist gotcha (`127.0.0.1` vs bridge IPs) before you save a tight list.

#### Security

- **Change passphrase** — rewraps the master key; revokes all tokens; shows a new root token once. Update every agent afterward.
- **Rotate master key** — new master, rewraps secrets, rewrites `unseal.key`, revokes all tokens. Use when you think the master key leaked.

#### Backup

| Download | Format | Contains | Use when |
|----------|--------|----------|----------|
| **Encrypted snapshot** | AVS2 (`.avs`) | `vault.db` + `unseal.key` | Full disaster recovery of *this* vault |
| **Encrypted export** | `.ave` | Secret records only | Migrate/copy secret values without cloning vault identity |

Both downloads ask for their own passphrase (min 12 characters). Store the file and that passphrase together offline.

Restore (snapshot) and import (`.ave`) are **CLI-only**. See [CLI](cli.md) and [Security & backup](security-and-backup.md).

## Session security (what the UI does for you)

- Session cookie: HttpOnly, SameSite=Lax; Secure when the request is HTTPS (or `X-Forwarded-Proto: https`)
- Mutating calls require a CSRF header that matches the CSRF cookie
- Login attempts are rate-limited

You do not need to manage CSRF yourself in the browser—the UI JavaScript handles it.

## When to use the UI vs CLI

| Task | Use the UI | Use CLI / API |
|------|------------|---------------|
| Browse / edit secrets | Yes | Yes |
| Read operator docs | Yes (`/ui/docs`) | Repo `docs/` |
| Configure HTTPS / allowlist | Yes | Settings writes are UI-session only |
| Mint / revoke tokens | No | `vault token …` |
| Download snapshot / export | Yes | Also `vault backup` / `vault export` |
| Restore snapshot / import `.ave` | No | CLI only |
| Agent automation | No | MCP / CLI / REST |
