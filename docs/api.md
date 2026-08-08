# HTTP API reference

Machine-oriented reference for `/v1`. Day to day, humans usually prefer the [Admin UI](admin-ui.md) or [CLI](cli.md); agents and custom clients use these routes.

Base URL examples:

- `http://localhost:8200`
- `http://<hostname>:8200`
- `https://vault.example.com`

Unless noted, endpoints require:

```http
Authorization: Bearer avt_…
Content-Type: application/json
```

JSON errors look like `{"error":"…"}`. An empty IP allowlist (the default) does not affect these routes; a non-empty allowlist returns `403` for clients outside the list.

## Auth and scopes

| Scope | Secrets CRUD | Unlock | Lock / rotate / tokens / backup / audit |
|-------|--------------|--------|----------------------------------------|
| `agent` | ✓ | ✓ | ✗ (`403`) |
| `admin` | ✓ | ✓ | ✓ |

UI session auth is separate (cookie + CSRF) under `/ui/*` and is not documented here as a public integration surface.

---

## `GET /health`

No auth. Does **not** expose sealed state.

```bash
curl -s "$AGENT_VAULT_URL/health"
# {"ok":true}
```

---

## Unlock & lock

### `POST /v1/unlock`

Any authenticated token. Rate-limited.

```bash
curl -sS -X POST "$AGENT_VAULT_URL/v1/unlock" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"your-passphrase"}'
```

Or with the unseal key hex:

```bash
curl -sS -X POST "$AGENT_VAULT_URL/v1/unlock" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"unseal_key_hex":"<64-char-hex>"}'
```

### `POST /v1/lock`

**Admin** only.

```bash
curl -sS -X POST "$AGENT_VAULT_URL/v1/lock" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN"
```

---

## Secrets

### Create — `POST /v1/secrets`

```bash
curl -sS -X POST "$AGENT_VAULT_URL/v1/secrets" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "openai.api_key",
    "type": "api_key",
    "secret": "sk-…",
    "tags": ["openai","agents"],
    "notes": "prod"
  }'
```

Types: `api_key` | `login` | `ssh_key` | `token` | `note`.  
Optional: `username`, `url`, `metadata` (string map).

Response is metadata (secret value not echoed).

### List — `GET /v1/secrets`

```bash
curl -sS "$AGENT_VAULT_URL/v1/secrets" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN"
```

### Get — `GET /v1/secrets/{name}`

Metadata only by default. Reveal with `?reveal=1`.

```bash
curl -sS "$AGENT_VAULT_URL/v1/secrets/openai.api_key?reveal=1" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN"
```

### Update — `PUT /v1/secrets/{name}`

Same body shape as create. Name in the path wins.

### Delete — `DELETE /v1/secrets/{name}`

`204` on success.

### Search — `GET /v1/search`

Query params: `q`, `tag`, `type` (any combination).

```bash
curl -sS "$AGENT_VAULT_URL/v1/search?q=openai&tag=agents" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN"
```

---

## Tokens (admin)

### List — `GET /v1/tokens`

```bash
curl -sS "$AGENT_VAULT_URL/v1/tokens" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN"
```

Returns `id`, `label`, `scope`, `created_at` (never the raw token).

### Create — `POST /v1/tokens`

```bash
curl -sS -X POST "$AGENT_VAULT_URL/v1/tokens" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label":"windsurf","scope":"agent"}'
```

`scope` defaults to `agent` if omitted. Response includes plaintext `token` **once**.

### Revoke — `DELETE /v1/tokens/{id}`

`204` on success. `409` if it would remove the last admin token.

---

## Passphrase & master (admin)

### `POST /v1/change-passphrase`

```bash
curl -sS -X POST "$AGENT_VAULT_URL/v1/change-passphrase" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"old_passphrase":"…","new_passphrase":"…"}'
```

Revokes all tokens; returns a new root token.

### `POST /v1/rotate-master`

```bash
curl -sS -X POST "$AGENT_VAULT_URL/v1/rotate-master" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"…"}'
```

---

## Audit (admin)

### `GET /v1/audit?limit=50`

```bash
curl -sS "$AGENT_VAULT_URL/v1/audit?limit=50" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN"
```

---

## Backup (admin)

### Encrypted snapshot — `POST /v1/backup/snapshot`

Body: `{"snapshot_passphrase":"…"}` (min 12 chars).  
Response: binary AVS2 blob (`Content-Disposition: agent-vault-snapshot.avs`).  
`GET` returns `405`.

```bash
curl -sS -X POST "$AGENT_VAULT_URL/v1/backup/snapshot" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_passphrase":"snapshot-pass…"}' \
  -o vault.avs
```

### Encrypted export — `POST /v1/backup/export`

```bash
curl -sS -X POST "$AGENT_VAULT_URL/v1/backup/export" \
  -H "Authorization: Bearer $AGENT_VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"backup_passphrase":"export-pass…"}' \
  -o secrets.ave
```

Vault must be unsealed. Restore/import are CLI filesystem operations, not HTTP.

---

## Status codes (common)

| Code | Meaning |
|------|---------|
| `200` / `201` / `204` | Success |
| `400` | Validation / bad JSON / weak passphrase |
| `401` | Missing/invalid bearer token |
| `403` | Scope or IP allowlist denial |
| `404` | Secret/token not found |
| `409` | Conflict (e.g. last admin) |
| `429` | Login/unlock rate limit |
| `503` | Vault sealed |

## Headers worth knowing

Successful API responses include security headers (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, etc.). Revealed secrets and backup downloads set `Cache-Control: no-store`.
