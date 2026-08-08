# Agent Vault Security Follow-ups — Design Spec

Depends on Phase 2c HTTPS/Settings and the auth/HTTP hardening slice.

## Order

1. **Token scopes + per-token revoke** — foundation for least privilege
2. **Encrypted snapshots** — remove plaintext `unseal.key` from backup archives
3. **IP allowlist** — optional network gate for public exposure

SSO remains out of scope (separate product decision).

---

## 1. Token scopes + revoke

### Scopes

| Scope | Capabilities |
|-------|----------------|
| `admin` | Full API: secrets CRUD, tokens, backups, lock/unlock, passphrase/master rotate, audit |
| `agent` | Secrets list/get/create/update/delete/search only (incl. reveal). No token admin, no backups, no rotate/change-passphrase, no lock |

UI passphrase sessions remain full operator access (not bearer-scoped).

### Data model

`tokens.scope TEXT NOT NULL DEFAULT 'admin'` via SQLite migration on open.

- Init root token → `admin`
- `POST /v1/tokens` body: `{ "label", "scope" }` — `scope` defaults to `agent`; only `admin` callers may mint tokens; only `admin` may mint `admin`
- `GET /v1/tokens` — list `{id,label,scope,created_at}` (admin)
- `DELETE /v1/tokens/{id}` — revoke one token (admin); refuse deleting the last remaining `admin` token

### Auth context

`Authenticate` returns label + scope. Middleware enforces scope on privileged routes.

---

## 2. Encrypted snapshots

### Format

- **v1** (legacy): `.avs.tar.gz` with plaintext `vault.db` + `unseal.key` — restore still supported
- **v2**: magic `AVS2` + Argon2id/AES-GCM wrapping the tar.gz bytes (same envelope style as `.ave`)

New downloads always produce v2. Passphrase min length = 12 (shared policy).

### API / CLI / UI

- Snapshot download becomes **POST** with `{ "snapshot_passphrase" }` (GET returns 405)
- `vault backup --passphrase` required; `vault restore --passphrase` for v2 (optional for v1)
- UI Settings backup prompts for snapshot passphrase (like export)

---

## 3. IP allowlist

### Settings

- `ip_allowlist` — newline/comma-separated CIDRs/IPs stored in settings; empty = allow all
- Enforced on `/ui/*` and `/v1/*` when non-empty; `/health` always allowed
- Client IP via `RemoteAddr`, or `X-Forwarded-For` when `AGENT_VAULT_TRUST_PROXY=1`
- Admin UI Settings section to edit allowlist; API `PUT` settings extended

Failed allowlist → `403` with generic message; audit `ip_deny` optional (rate-friendly).

---

## Success criteria

- Agent token cannot mint tokens or download backups
- Admin can list/revoke tokens; last admin protected
- New snapshots require passphrase; restore without passphrase fails for v2
- Non-empty allowlist blocks foreign IPs
- `go test ./...` + smokes pass
