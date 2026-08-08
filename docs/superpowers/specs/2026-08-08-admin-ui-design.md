# Agent Vault Admin UI — Design Spec (Phase 2a)

**Date:** 2026-08-08  
**Status:** Ready for user review  
**Repo:** `agent-vault`  
**Depends on:** Phase 1 (verified on beast; host port **8200**)

## Purpose

Ship an embedded Admin UI so the single vault owner can manage structured credentials (logins, API keys, tokens, SSH keys, notes) in a browser, with passphrase session login — without changing the agent/CLI/MCP bearer-token API.

## Goals

1. Browser CRUD for all existing secret types with search/filter.
2. Reveal-on-demand and copy; never show secrets in lists or URLs.
3. Vault lock/unlock and recent audit view in the UI.
4. HttpOnly session auth via vault passphrase (no long-lived API token in JavaScript).
5. Same single Docker image and Compose service; UI at `http://beast:8200/ui`.

## Non-goals (this slice)

- HTTPS / reverse-proxy Compose profile (Phase 2b).
- Backup / export tooling (Phase 2c).
- Secret rotation helpers (Phase 2d).
- Multi-user accounts, SSO, or RBAC.
- Separate UI container or Node SPA toolchain.
- Mobile-native apps.

## Trust model

Unchanged from Phase 1: single user on beast. The UI is an alternate front door to the same vault. Session proves knowledge of the vault passphrase. Bearer tokens remain for agents.

## Architecture

```text
Browser ── (private network; HTTPS later) ──► vault-server :8200
                                               ├─ /ui/*       templates + static (embed.FS)
                                               ├─ /ui/login   passphrase → HttpOnly session
                                               ├─ /ui/api/*   session-auth JSON
                                               └─ /v1/*       existing bearer API (agents)
                                                    │
                                                    ▼
                                               vault service + SQLite (unchanged core)
```

- Admin UI is embedded in `vault-server` (Approach: Go `html/template` + minimal vanilla JS).
- No second Compose service.
- Host mapping remains **8200→8080**; container still binds `0.0.0.0:$PORT`.

## Session authentication

| Topic | Decision |
|-------|----------|
| Credential | Vault passphrase (same material used to unwrap master key) |
| Cookie | `agent_vault_session`; HttpOnly; `SameSite=Lax`; `Secure` when request is TLS / `X-Forwarded-Proto=https` |
| Store | In-memory session map in the server process (single replica) |
| TTL | Idle 12h or absolute 24h (whichever first); logout clears cookie + server entry |
| Login behavior | Verify passphrase; if sealed, unlock as part of successful login; always create session on success |
| CSRF | Mutating `/ui/api/*` requires matching CSRF token (cookie + header or form field) |
| Audit actor | `ui` (optionally `ui:<8-char session prefix>`) |

Unauthenticated `/ui` requests redirect to `/ui/login`. `/v1` remains bearer-only and does not accept session cookies.

## UI surfaces

| Page | Purpose |
|------|---------|
| Login | Passphrase; show sealed/unsealed status |
| Secrets list | Search by query/type/tag; no secret/username values |
| New secret | Type picker + create form |
| Secret detail/edit | View/edit fields; Reveal; Copy; Delete with confirm |
| Vault controls | Lock / unlock (passphrase); sealed banner when locked |
| Audit | Recent events; never includes secret values |

### Secret types (unchanged)

`api_key` | `login` | `ssh_key` | `token` | `note`

Forms show type-appropriate fields (e.g. username+secret+url for `login`).

## UI JSON API (session-auth)

Thin wrappers over existing vault operations. Suggested paths:

| Method | Path | Behavior |
|--------|------|----------|
| POST | `/ui/login` | Passphrase → session cookie |
| POST | `/ui/logout` | Clear session |
| GET | `/ui/api/status` | `{sealed, authenticated}` |
| GET | `/ui/api/secrets` | List (no reveal) |
| GET | `/ui/api/search` | `q`, `tag`, `type` |
| POST | `/ui/api/secrets` | Create |
| GET | `/ui/api/secrets/{name}` | Metadata; `?reveal=1` for secret/username |
| PUT | `/ui/api/secrets/{name}` | Update |
| DELETE | `/ui/api/secrets/{name}` | Delete |
| POST | `/ui/api/lock` | Seal vault |
| POST | `/ui/api/unlock` | Unlock with passphrase |
| GET | `/ui/api/audit` | Recent events |

Errors mirror Phase 1 semantics where applicable (`401` session, `403` CSRF, `404`, `409`, `503` sealed).

## Frontend implementation

- Templates and static assets under e.g. `internal/ui/` with `embed.FS`.
- Minimal vanilla JS for reveal, copy-to-clipboard, search debounce, delete confirm.
- CSS variables for a calm utility palette; avoid purple-gradient / glow / dense card chrome.
- Responsive enough for phone-width forms; primary target is desktop on the LAN/Tailscale.

## UX rules for secrets

1. List and search never include `secret` or `username`.
2. Reveal is an explicit action that calls `?reveal=1` once.
3. Secrets never appear in query strings, path segments, or audit payloads.
4. Delete requires confirmation.
5. When sealed, mutating/reveal routes return clear errors; UI shows a sealed banner and lock/unlock controls.

## Repository layout (additions)

```text
internal/ui/           # templates, static, session store, handlers
internal/api/          # mount UI routes alongside /v1 (or wire from main)
cmd/vault-server/      # unchanged entry; Handler includes /ui
```

Exact file split is an implementation detail; keep UI package focused and separate from bearer `/v1` handlers.

## Testing strategy

- Unit/integration: login success/failure, session expiry, CSRF rejection.
- httptest: CRUD + reveal via session cookie; sealed `503` behavior.
- Template render smoke for login + list.
- Regression: existing `/v1` bearer tests and `scripts/smoke.sh` still pass.

## Deploy impact

- No Compose service changes required for UI itself (same image).
- README: document `http://beast:8200/ui` and passphrase login.
- Skills: optional one-line note that humans may use the Admin UI; agents continue MCP/CLI.

## Phase 2 sequencing (after this slice)

| Slice | Scope |
|-------|--------|
| **2a (this)** | Admin UI |
| **2b** | Backup / export |
| **2c** | HTTPS reverse-proxy Compose profile |
| **2d** | Secret rotation helpers |

## Success criteria

1. Operator opens `/ui`, logs in with passphrase, creates/edits/deletes each secret type.
2. Reveal and copy work; lists never show secret material.
3. Lock/unlock and audit work from the UI.
4. CLI/MCP/`/v1` behavior unchanged on host port 8200.
5. Single Docker image deploy on beast continues to work.
6. Automated tests cover session auth and UI API critical paths.

## Resolved decisions

| Topic | Decision |
|-------|----------|
| Phase order | Admin UI first, then backup → HTTPS → rotation |
| Auth | Passphrase → HttpOnly server session |
| Delivery | Embedded in `vault-server` |
| UI scope | CRUD + reveal + lock/unlock + audit |
| Frontend | Go templates + minimal JS (no SPA) |
| Host port | 8200 (already on main) |
