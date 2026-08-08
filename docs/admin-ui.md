# Admin UI

The Admin UI is for **humans**. Agents should use MCP, CLI, or REST with bearer tokens—not the browser.

## Open it

- Local: `http://localhost:8200/ui`
- On beast: `http://beast:8200/ui`
- With HTTPS configured: `https://<your-hostname>/ui`

Log in with the vault **passphrase** (the same one used at init / unlock). Successful login also unseals the vault if it was sealed.

## What you can do

### Secrets

- List, search, create, edit, delete
- Reveal a secret’s value when needed (responses are marked non-cacheable)

### Chrome (every page)

- **Lock / Unlock** — seal or unseal without logging out
- Nav: Secrets, Audit, Settings

### Settings (`/ui/settings`)

This is the operator home.

**Network & HTTPS**

- Public hostname and Enable HTTPS
- Status (private URL, public URL, Caddyfile state, apply hint)
- Cloudflare grey-cloud checklist
- Optional **IP allowlist** (IPs/CIDRs; empty = allow all)

**Security**

- Change passphrase
- Rotate master key

**Backup**

- Download encrypted **snapshot** (AVS2 — prompts for a snapshot passphrase, min 12 chars)
- Download encrypted **export** (`.ave` — separate backup passphrase)

Restore and import are **CLI-only** (see [CLI](cli.md) and [Security & backup](security-and-backup.md)).

## Session security

- Session cookie: HttpOnly, SameSite=Lax, Secure when the request is HTTPS / `X-Forwarded-Proto: https`
- Mutating calls need the CSRF header (`X-CSRF-Token`) matching the CSRF cookie
- Login attempts are rate-limited

## When to use the UI vs CLI

| Task | UI | CLI / API |
|------|----|-----------|
| Browse / edit secrets | ✓ | ✓ |
| Configure HTTPS / allowlist | ✓ | — (settings API is UI session) |
| Mint / revoke tokens | — | ✓ (`vault token …`) |
| Restore snapshot / import `.ave` | — | ✓ |
| Agent automation | — | ✓ |
