# HTTPS & Settings (Phase 2c) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an Admin UI Settings home (hostname/HTTPS, security ops, backups) that persists config and generates a Caddyfile, plus an optional Compose `https` profile so Let’s Encrypt TLS can front the vault for cloud agents — while first boot still works with no domain on private `:8200`.

**Architecture:** Settings live in SQLite; on save the vault writes `/caddy-config/Caddyfile`. Compose `https` profile runs Caddy with that config volume and proxies to `agent-vault:8080`. Settings UI consolidates passphrase/rotate/backup and embeds Cloudflare DNS-only setup steps.

**Tech Stack:** Existing Go vault/UI stack, SQLite settings, Caddy 2 Alpine via Docker Compose profiles, `html/template` + vanilla JS.

## Global Constraints

- Private HTTP remains host **8200** → container `8080`.
- Cloudflare **DNS-only (grey cloud)** + Let’s Encrypt via Caddy; no orange-cloud / Origin certs this slice.
- First boot: no hostname required; `https_enabled` defaults false.
- Hostname: FQDN only (no scheme/path); validate before save.
- Settings writes are UI session + CSRF only (no public `/v1` settings write).
- Caddy terminates TLS; vault stays HTTP on docker network; honor `X-Forwarded-Proto`.
- Do not store Cloudflare API tokens.
- Module `github.com/cswink267/agent-vault`.
- Stay on branch `cursor/https-settings-design-dd00`; do not create unrelated branches.
- Preserve `go test ./...` and existing smoke scripts.

## File Structure

| Path | Responsibility |
|------|----------------|
| `internal/store/settings.go` | Settings table CRUD |
| `internal/settings/caddyfile.go` | Generate active/disabled Caddyfile text |
| `internal/settings/validate.go` | Hostname validation |
| `internal/vault/settings.go` | Get/Put settings + write Caddyfile to config dir |
| `internal/ui/handlers.go` | GET/PUT `/ui/api/settings`, page route |
| `internal/ui/templates/settings.html` | Settings page sections |
| `internal/ui/static/app.js` / `app.css` | Settings UI logic/styles |
| `internal/ui/templates/layout.html` | Settings nav; slim chrome (move ops into Settings) |
| `cmd/vault-server/main.go` | Env `AGENT_VAULT_CADDY_CONFIG_DIR` |
| `deploy/docker-compose.yml` + root compose | `https` profile + volumes |
| `deploy/caddy/Caddyfile.disabled` | Optional seed stub |
| `README.md`, skills | HTTPS + Settings + Cloudflare checklist |

---

### Task 1: Settings persistence + hostname validation + Caddyfile generator

**Files:**
- Create: `internal/store/settings.go` (or extend `store.go` if tiny)
- Modify: `internal/store/store.go` — migrate `settings` table in `Open`
- Create: `internal/settings/validate.go`
- Create: `internal/settings/caddyfile.go`
- Create: `internal/settings/*_test.go`
- Modify: `internal/store/store_test.go`

**Interfaces:**
- Consumes: `*store.Store`
- Produces:
  - `type Settings struct { PublicHostname string; HTTPSEnabled bool; UpdatedAt string }`
  - `func (s *Store) GetSettings() (Settings, error)` — defaults empty/false if missing
  - `func (s *Store) PutSettings(Settings) error` — upsert; set UpdatedAt RFC3339 UTC
  - `func ValidateHostname(host string) error` — empty OK; else DNS label rules; reject `://`, `/`, spaces
  - `func RenderCaddyfile(hostname string, enabled bool) string` — active site block or disabled stub
  - Active template (hostname sanitized/validated before call):
    ```
    example.com {
    	reverse_proxy agent-vault:8080
    }
    ```
  - Disabled stub must include a clear comment `# agent-vault https disabled` and not claim real hostnames

Schema:
```sql
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
```
Store keys: `public_hostname`, `https_enabled` (`"true"`/`"false"`), `updated_at`.

- [ ] **Step 1: Write failing tests**

```go
func TestValidateHostname(t *testing.T) {
	if err := settings.ValidateHostname(""); err != nil { t.Fatal(err) }
	if err := settings.ValidateHostname("vault.example.com"); err != nil { t.Fatal(err) }
	if err := settings.ValidateHostname("http://vault.example.com"); err == nil { t.Fatal("expected error") }
}

func TestRenderCaddyfile(t *testing.T) {
	active := settings.RenderCaddyfile("vault.example.com", true)
	// contains hostname + reverse_proxy agent-vault:8080
	disabled := settings.RenderCaddyfile("", false)
	// contains "https disabled"
}

func TestStoreSettingsRoundTrip(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "v.db"))
	defer st.Close()
	in := store.Settings{PublicHostname: "vault.example.com", HTTPSEnabled: true}
	if err := st.PutSettings(in); err != nil { t.Fatal(err) }
	out, err := st.GetSettings()
	// assert fields; UpdatedAt non-empty
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
go test ./internal/settings/ ./internal/store/ -v
```

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run — expect PASS**

```bash
go test ./internal/settings/ ./internal/store/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/settings internal/store
git commit -m "feat(settings): add settings store, hostname validation, Caddyfile render"
```

---

### Task 2: Vault settings service + Caddyfile write to config dir

**Files:**
- Create: `internal/vault/settings.go`
- Modify: `internal/vault/vault_test.go`
- Modify: `cmd/vault-server/main.go` — pass config dir into vault or set on Vault

**Interfaces:**
- Consumes: store settings + `settings.RenderCaddyfile` / `ValidateHostname`
- Produces:
  - `func (v *Vault) SetCaddyConfigDir(dir string)` or field set at Open/Init
  - `func (v *Vault) GetSettings() (SettingsView, error)`
  - `func (v *Vault) UpdateSettings(publicHostname string, httpsEnabled bool) (SettingsView, error)`
  - `type SettingsView` includes stored fields + `PrivateBaseURL`, `PublicBaseURL`, `CaddyfileStatus` (`active`|`disabled`), `ApplyHint`, `CaddyConfigPath`
  - On Update: validate hostname; PutSettings; write `Caddyfile` atomically (`*.tmp` + rename) under config dir if dir set; if dir empty, skip file write but still persist (dev/test)
  - `PublicBaseURL`: `https://`+hostname when hostname set, else `""`
  - `PrivateBaseURL`: default `http://localhost:8200` (constant or env `AGENT_VAULT_PRIVATE_BASE_URL`)
  - `ApplyHint`: when active, `docker compose --profile https up -d`; else explain enable DNS first
  - Audit `settings_update` with empty secret name

Env: `AGENT_VAULT_CADDY_CONFIG_DIR` (default `/caddy-config` in container; empty OK locally).

- [ ] **Step 1: Write failing tests** with temp caddy dir — UpdateSettings writes file contents matching RenderCaddyfile; invalid hostname errors; disabled writes stub

- [ ] **Step 2: Implement**

Wire `Open`/`Init` to leave `caddyConfigDir` settable; `main` reads env and sets it after Open/Init.

- [ ] **Step 3: Run**

```bash
go test ./internal/vault/ -v
```

- [ ] **Step 4: Commit**

```bash
git add internal/vault cmd/vault-server
git commit -m "feat(vault): persist settings and write generated Caddyfile"
```

---

### Task 3: UI API + Settings page (network/HTTPS + Cloudflare checklist)

**Files:**
- Modify: `internal/ui/handlers.go`, `handlers_test.go`
- Create: `internal/ui/templates/settings.html`
- Modify: `internal/ui/templates/layout.html` — add Settings nav link
- Modify: `internal/ui/static/app.js`, `app.css`
- Modify: `internal/ui/embed` if needed (templates auto via embed)

**Interfaces:**
- `GET /ui/settings` — page auth
- `GET /ui/api/settings` — session JSON
- `PUT /ui/api/settings` — session+CSRF body `{public_hostname, https_enabled}`
- Page sections: Network & HTTPS (form + Cloudflare grey-cloud checklist + status + apply hint), placeholders for Security/Backup filled in Task 4

Cloudflare checklist copy must include: A/AAAA to this host public IP; **DNS only (grey cloud)**; forward 80/443; wait for DNS; save+enable; run compose profile command from `apply_hint`.

- [ ] **Step 1: API tests** — unauth 401; PUT without CSRF 403; PUT valid updates GET; invalid hostname 400

- [ ] **Step 2: Page test** — `/ui/settings` redirects when logged out; 200 with “Settings” when logged in

- [ ] **Step 3: Implement handlers + template + JS save**

- [ ] **Step 4: Run**

```bash
go test ./internal/ui/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/ui
git commit -m "feat(ui): add Settings page and settings API with Cloudflare guide"
```

---

### Task 4: Move security + backup into Settings; slim chrome

**Files:**
- Modify: `internal/ui/templates/layout.html` — remove backup/passphrase/rotate panels from global chrome (keep Lock/Unlock + nav)
- Modify: `internal/ui/templates/settings.html` — Security + Backup sections (reuse form IDs/handlers from app.js)
- Modify: `internal/ui/static/app.js` — init settings section wiring; ensure change-passphrase/rotate/backup still work on settings page
- Modify: CSS for settings layout (sections, calm utility style)

**Interfaces:**
- No new backend APIs (reuse existing)
- Settings page is the operator home for those actions

- [ ] **Step 1: Manual/UI test update** — ensure list page no longer shows passphrase forms; settings page contains them; existing API tests still pass

- [ ] **Step 2: Implement template/JS moves**

- [ ] **Step 3: Run**

```bash
go test ./internal/ui/ ./internal/api/ -v
bash scripts/smoke-ui.sh
```

- [ ] **Step 4: Commit**

```bash
git add internal/ui
git commit -m "feat(ui): consolidate security and backup controls into Settings"
```

---

### Task 5: Compose `https` profile + vault caddy-config mount

**Files:**
- Modify: `deploy/docker-compose.yml`
- Modify: `docker-compose.yml` (root wrapper — keep parity)
- Create: `deploy/caddy/README.md` (short: volume is generated by vault; do not hand-edit in git)
- Modify: `cmd/vault-server` env already done — ensure compose sets `AGENT_VAULT_CADDY_CONFIG_DIR=/caddy-config`

**Compose shape:**

```yaml
services:
  agent-vault:
    environment:
      AGENT_VAULT_CADDY_CONFIG_DIR: /caddy-config
    volumes:
      - vault-data:/data
      - caddy-config:/caddy-config

  caddy:
    profiles: ["https"]
    image: caddy:2.8-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - caddy-config:/etc/caddy:ro
      - caddy-data:/data
    depends_on:
      - agent-vault
    restart: unless-stopped

volumes:
  vault-data:
  caddy-config:
  caddy-data:
```

Caddy reads `/etc/caddy/Caddyfile` by default — generate that filename into the shared volume root.

- [ ] **Step 1: Validate compose**

```bash
docker compose -f deploy/docker-compose.yml config >/dev/null
docker compose -f deploy/docker-compose.yml --profile https config >/dev/null
```

If Docker unavailable, still author files; note in report.

- [ ] **Step 2: Commit**

```bash
git add deploy docker-compose.yml
git commit -m "feat(deploy): add Caddy https Compose profile and config volume"
```

---

### Task 6: Docs, skills, smoke-settings check

**Files:**
- Modify: `README.md` — Settings + Cloudflare grey-cloud + `https` profile; Phase 2 preview update
- Modify: `skills/*/SKILL.md` — HTTPS base URL when configured; Settings for humans
- Create: `scripts/smoke-settings.sh` — init server with temp caddy dir; login; PUT settings; assert Caddyfile on disk; GET settings

**Interfaces:**
- smoke must not print secrets/tokens
- assert active Caddyfile contains hostname and `reverse_proxy agent-vault:8080`

- [ ] **Step 1: Write and run smoke-settings.sh**

```bash
chmod +x scripts/smoke-settings.sh
bash scripts/smoke-settings.sh
go test ./...
bash scripts/smoke.sh
bash scripts/smoke-ui.sh
bash scripts/smoke-backup.sh
```

- [ ] **Step 2: README + skills**

- [ ] **Step 3: Commit**

```bash
git add README.md skills scripts/smoke-settings.sh
git commit -m "docs: document HTTPS Settings flow and add smoke-settings"
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| Settings table + hostname validation | 1 |
| Caddyfile active/disabled render | 1, 2 |
| Vault write to config dir + view fields | 2 |
| Settings UI + Cloudflare checklist | 3 |
| Security + backup in Settings | 4 |
| Compose https profile | 5 |
| Docs + smoke | 6 |
| First boot without domain | 2–5 defaults |
| No CF API tokens / no orange cloud | Global + copy in Task 3 |

## Plan self-review notes

- Caddyfile path is volume root `Caddyfile` mounted at `/etc/caddy` for Caddy and `/caddy-config` for vault (same files).
- Atomic write via temp+rename avoids Caddy reading half-written files.
- Existing WantSecure() already handles `X-Forwarded-Proto`.
- No placeholders remaining for Phase 2c scope.
