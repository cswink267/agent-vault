# Agent Vault HTTPS & Settings — Design Spec (Phase 2c)

**Date:** 2026-08-08  
**Status:** Ready for user review  
**Repo:** `agent-vault`  
**Depends on:** Phase 1, Admin UI (2a), backup/export (2b), passphrase/master rotation on `main`  
**Private HTTP port:** host **8200** → container `8080`

## Purpose

Add an Admin UI **Settings** home for operator configuration — especially a public hostname for HTTPS — and an optional Compose **`https` profile** (Caddy + Let’s Encrypt) so cloud agents can reach the vault over TLS. First boot must work with **no domain configured**.

## Goals

1. Settings page consolidating network/HTTPS, security ops (change passphrase, rotate master), and backups.
2. Persist `public_hostname` + `https_enabled`; generate a Caddyfile for the reverse proxy.
3. Cloudflare **DNS-only (grey cloud)** setup instructions embedded in Settings.
4. Optional `https` Compose profile: Caddy on 80/443 → `agent-vault:8080` with ACME.
5. Keep private LAN access on `:8200` without requiring HTTPS.

## Non-goals

- Tailscale / Cloudflare orange-cloud / Origin certificates (this slice is DNS-only + LE on the host).
- Storing Cloudflare API tokens or automating DNS record creation.
- Built-in IP allowlists or SSO (may come later).
- Vault process terminating TLS itself (Caddy terminates TLS).
- Changing agent bearer-token auth model.

## Trust & network model

| Path | Use |
|------|-----|
| `http://localhost:8200` (or LAN IP) | Private HTTP; default first-boot access |
| `https://<public_hostname>` | Public HTTPS via Caddy; cloud agents / remote UI |

TLS encrypts transit; **bearer tokens and UI passphrase sessions remain mandatory**. Do not expose without strong credentials.

## Architecture

```text
Internet (cloud agents / remote browser)
        │ HTTPS :443 (Let's Encrypt)
        ▼
   ┌─────────┐  HTTP :8080 (docker net)   ┌─────────────┐
   │  Caddy  │ ─────────────────────────► │ agent-vault │
   │ https   │  X-Forwarded-Proto=https   │ /v1 + /ui   │
   │ profile │                            └──────┬──────┘
   └────┬────┘                                   │
        │ reads generated Caddyfile              │ Settings save
        ▼                                        ▼
   volume: caddy-config ◄──────── write Caddyfile + settings in SQLite
```

## Settings data model

Persist in SQLite (dedicated `settings` table **or** `vault_meta` keys — prefer small `settings` table for clarity):

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `public_hostname` | string | `""` | FQDN only, no scheme/port (e.g. `vault.example.com`) |
| `https_enabled` | bool | `false` | When true and hostname set, emit active Caddyfile site |
| `updated_at` | RFC3339 | — | Last Settings save |

Validation: hostname must match a conservative DNS name regex; reject URLs with `http://` or paths.

## Settings UI (`/ui/settings`)

Session-required page with sections:

### 1. Network & HTTPS

- Inputs: Public hostname, Enable HTTPS checkbox.
- **Cloudflare setup checklist** (DNS-only / grey cloud), shown whenever hostname is non-empty or user expands help:
  1. In Cloudflare DNS, add **A** (IPv4) and/or **AAAA** (IPv6) for the subdomain → this host's public IP (or CNAME if applicable).
  2. Set proxy status to **DNS only** (grey cloud), not Proxied.
  3. Ensure firewall/router forwards **80** and **443** to the machine running Compose.
  4. Wait for DNS to resolve publicly (`dig` / Cloudflare dashboard).
  5. Save Settings with **Enable HTTPS** checked, then start/reload the Compose `https` profile (command shown in UI).
- Status line: current private URL, suggested public URL `https://<hostname>`, whether Caddyfile is active/stub.
- On Save: persist settings, regenerate Caddyfile on config volume, return apply instructions.

### 2. Security

- Change passphrase (existing API).
- Rotate master key (existing API).
- Short warnings about token revocation (already documented behavior).

### 3. Backup

- Download snapshot / Download export (existing endpoints; CSRF rules unchanged).

### 4. About

- Sealed/unsealed status, note that LAN `:8200` remains available, link to README security notes.

Nav: add **Settings** to Admin UI chrome; optionally slim header by relying on Settings for passphrase/rotate/backup entry points (keep vault lock/unlock in chrome).

## API

| Method | Path | Auth | Behavior |
|--------|------|------|----------|
| GET | `/ui/api/settings` | session | Return settings + derived status fields |
| PUT | `/ui/api/settings` | session + CSRF | Update hostname/https_enabled; regenerate Caddyfile |
| (existing) | security + backup UI APIs | session (+ CSRF) | Unchanged |

No public unauthenticated settings write. Bearer `/v1` settings endpoints are **out of scope** this slice (YAGNI).

### GET `/ui/api/settings` response (illustrative)

```json
{
  "public_hostname": "vault.example.com",
  "https_enabled": true,
  "updated_at": "2026-08-08T21:00:00Z",
  "private_base_url": "http://localhost:8200",
  "public_base_url": "https://vault.example.com",
  "caddyfile_status": "active",
  "apply_hint": "docker compose --profile https up -d"
}
```

`private_base_url` may be informational/default; exact LAN hostname is operator-known.

## Caddyfile generation

Output path (container): e.g. `/caddy-config/Caddyfile` (Compose volume shared with Caddy).

**When `https_enabled` and hostname non-empty:**

```caddy
vault.example.com {
	reverse_proxy agent-vault:8080
}
```

(Host inlined from settings; Caddy obtains LE cert via HTTP-01 on :80.)

**Otherwise:** write a minimal stub (e.g. comment-only or `:80 { respond "agent-vault https disabled" 404 }`) and set `caddyfile_status` to `disabled` so accidentally starting the profile is obvious.

Vault must set `X-Forwarded-*` trust correctly — Caddy should forward `X-Forwarded-Proto` / `Host`. Existing UI `WantSecure()` already treats `X-Forwarded-Proto=https` as Secure cookies.

## Compose layout

**Default (unchanged):** `agent-vault` service, `8200:8080`, data volume.

**Profile `https`:**

| Service | Image | Ports | Volumes |
|---------|-------|-------|---------|
| `caddy` | `caddy:2-alpine` (pin minor as practical) | `80:80`, `443:443` | `caddy-config` (ro), `caddy-data` (certs) |

Vault service gains a mount of `caddy-config` (rw) for generation. Document:

```bash
# private only (first boot)
docker compose up -d

# after Settings hostname + DNS
docker compose --profile https up -d
```

Root `docker-compose.yml` and `deploy/docker-compose.yml` stay in sync (canonical under `deploy/`).

## Security notes (document in Settings + README)

- Use **grey cloud** only for this LE HTTP-01 setup; orange cloud breaks/complicates issuance and TLS modes.
- Prefer strong unique API tokens per agent; rotate after passphrase/master changes.
- Exposing `/ui` on the public hostname exposes the Admin UI — protect the passphrase; consider later IP allowlisting if needed.
- Do not commit real hostnames or certs into git; `.env` / Settings DB only.

## Testing

- Unit: hostname validation; Caddyfile active vs disabled content.
- API: GET/PUT settings auth + CSRF; PUT regenerates file in temp config dir.
- UI: settings page requires session; save flow.
- Compose: `docker compose -f deploy/docker-compose.yml --profile https config` when Docker available.
- Regression: `go test ./...`, `scripts/smoke.sh`, `scripts/smoke-ui.sh`, `scripts/smoke-backup.sh`.

## Docs & skills

- README: HTTPS profile, Settings flow, Cloudflare grey-cloud steps summary, agent URL `https://<hostname>`.
- Skills: note agents may use public HTTPS base URL when configured; humans use Settings for domain setup.

## Success criteria

1. Deploy without a domain: vault healthy on `:8200`, Settings shows HTTPS off.
2. Operator can set hostname later with in-UI Cloudflare DNS-only instructions.
3. Enabling HTTPS writes an active Caddyfile; `https` profile proxies TLS to the vault.
4. Settings hosts passphrase change, master rotate, and backup downloads.
5. Existing private HTTP and bearer `/v1` behavior remain intact.

## Resolved decisions

| Topic | Decision |
|-------|----------|
| Certs | Let’s Encrypt via Caddy on the host |
| DNS | Cloudflare DNS-only (grey cloud); manual records |
| First boot | No subdomain required |
| Settings | UI for hostname/HTTPS + security ops + backup |
| Apply model | Persist + generate Caddyfile; operator runs/reloads `https` profile |
| TLS terminator | Caddy (not vault binary) |

## Sequencing note

Rotation helpers largely shipped earlier. After this slice: optional hardening (IP allowlist, Cloudflare API automation) only if requested.
