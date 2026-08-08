# Backup & Export (Phase 2b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship on-demand snapshot backups and portable encrypted exports with CLI restore/import and Admin UI downloads, without changing agent bearer `/v1` secret CRUD.

**Architecture:** New `internal/backup` package builds `.avs.tar.gz` snapshots (safe SQLite copy + `unseal.key` + manifest) and `.ave` export blobs (Argon2id + AES-GCM over JSON secrets). Vault methods orchestrate listing/revealing secrets and auditing. API/UI expose download endpoints; CLI wraps client downloads plus local restore/import.

**Tech Stack:** Go stdlib (`archive/tar`, `compress/gzip`, `encoding/json`), existing `internal/crypto` (Argon2id, AES-GCM), `internal/vault`, `internal/api`, `internal/ui`, `internal/client`.

## Global Constraints

- Host port **8200**; module `github.com/cswink267/agent-vault`.
- Snapshot: `vault.db` + `unseal.key` + `manifest.json`; exclude `root.token` by default.
- Export requires unsealed vault + backup passphrase; sealed → 503.
- Restore/import are **CLI-only**; UI downloads only.
- Never log/audit secret values or backup passphrases.
- Restore refuses existing `vault.db` without `--force`.
- Import skips name conflicts unless `--overwrite`.
- No cron/cloud sync/HTTPS in this plan.
- Stay on branch `cursor/backup-export-design-dd00` (continue it); do not create unrelated branches.
- Preserve existing tests: `go test ./...`, `scripts/smoke.sh`, `scripts/smoke-ui.sh`.

## File Structure

| Path | Responsibility |
|------|----------------|
| `internal/backup/snapshot.go` | Build/extract `.avs.tar.gz` |
| `internal/backup/export.go` | Encrypt/decrypt `.ave` payload |
| `internal/backup/*_test.go` | Unit tests |
| `internal/store/store.go` | `VacuumInto(path)` for consistent DB copy |
| `internal/vault/backup.go` (or vault.go) | `WriteSnapshot`, `BuildExport`, audit |
| `internal/api/server.go` | `GET /v1/backup/snapshot`, `POST /v1/backup/export` |
| `internal/ui/handlers.go` + JS/CSS/layout | UI download endpoints + buttons |
| `internal/client/client.go` | Download helpers + import create/put loop |
| `cmd/vault/main.go` | `backup`, `restore`, `export`, `import` |
| `scripts/smoke-backup.sh` | Round-trip verification |
| `README.md`, skills | Operator docs |

---

### Task 1: Snapshot archive helpers + SQLite VacuumInto

**Files:**
- Create: `internal/backup/snapshot.go`
- Create: `internal/backup/snapshot_test.go`
- Modify: `internal/store/store.go`
- Modify: `internal/store/store_test.go`

**Interfaces:**
- Consumes: `*store.Store`, filesystem paths
- Produces:
  - `const SnapshotFormat = "agent-vault-snapshot"`
  - `const SnapshotVersion = 1`
  - `type Manifest struct { Format string; Version int; CreatedAt string; Source string }`
  - `func WriteSnapshotTarGz(w io.Writer, dbPath, unsealKeyPath string, manifest Manifest) error` — reads files from disk into tar.gz members `vault.db`, `unseal.key`, `manifest.json`
  - `func ExtractSnapshotTarGz(r io.Reader, destDir string) (Manifest, error)` — writes members; validates format/version
  - `func (s *Store) VacuumInto(path string) error` — `VACUUM INTO ?` (SQLite)

- [ ] **Step 1: Write failing store + snapshot tests**

```go
func TestVacuumIntoAndSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vault.db"))
	// SetMeta, Close not required for vacuum
	copyPath := filepath.Join(dir, "copy.db")
	if err := st.VacuumInto(copyPath); err != nil { t.Fatal(err) }
	// write fake unseal.key
	// backup.WriteSnapshotTarGz to buffer
	// ExtractSnapshotTarGz into dest
	// assert files exist + manifest fields
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
go test ./internal/backup/ ./internal/store/ -v
```

- [ ] **Step 3: Implement VacuumInto + snapshot write/extract**

Tar members must be exactly `vault.db`, `unseal.key`, `manifest.json`. File mode for extracted keys `0600`.

- [ ] **Step 4: Run — expect PASS**

```bash
go test ./internal/backup/ ./internal/store/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/backup internal/store
git commit -m "feat(backup): add snapshot archive helpers and SQLite VacuumInto"
```

---

### Task 2: Encrypted export format

**Files:**
- Create: `internal/backup/export.go`
- Create: `internal/backup/export_test.go`

**Interfaces:**
- Consumes: `internal/crypto` (NewSalt, DeriveKey, aes via Seal/Open **or** dedicated file encryption using same primitives)
- Produces:
  - `const ExportMagic = "AVE1"`
  - `type ExportRecord struct { Name, Type, Username, Secret, URL, Notes string; Tags []string; Metadata map[string]string }`
  - `func SealExport(passphrase string, records []ExportRecord) ([]byte, error)`
  - `func OpenExport(passphrase string, blob []byte) ([]ExportRecord, error)`

File layout (version 1):
```
magic "AVE1" (4 bytes)
salt_len uint16 BE + salt
nonce_len uint16 BE + nonce
ciphertext ([]byte remainder)  // AES-GCM of JSON []ExportRecord; key = Argon2id(passphrase, salt)
```

Prefer implementing GCM directly in `export.go` with `crypto.DeriveKey` + stdlib AES (same params as vault: time=3, memory=64MiB, threads=4) — do not reuse envelope DEK wrapping unless convenient.

- [ ] **Step 1: Write failing round-trip test**

```go
func TestExportSealOpenRoundTrip(t *testing.T) {
	recs := []backup.ExportRecord{{Name: "k", Type: "api_key", Secret: "sk-test", Tags: []string{"t"}}}
	blob, err := backup.SealExport("backup-pass", recs)
	out, err := backup.OpenExport("backup-pass", blob)
	// assert equal; wrong pass fails
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
go test ./internal/backup/ -run TestExport -v
```

- [ ] **Step 3: Implement SealExport/OpenExport**

- [ ] **Step 4: Run — expect PASS**

```bash
go test ./internal/backup/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/backup
git commit -m "feat(backup): add AES-GCM portable export format"
```

---

### Task 3: Vault snapshot + export orchestration

**Files:**
- Create: `internal/vault/backup.go`
- Modify: `internal/vault/vault_test.go`

**Interfaces:**
- Consumes: `v.dataDir`, `v.store.VacuumInto`, `backup.*`, `Get`/`List` with reveal
- Produces:
  - `func (v *Vault) WriteSnapshot(actor string, w io.Writer) error` — vacuum DB to temp under dataDir, read `unseal.key`, write tar.gz, audit `backup_snapshot`, cleanup temp
  - `func (v *Vault) BuildExport(actor, backupPassphrase string) ([]byte, error)` — require unsealed; list names; get each with reveal; seal export; audit `backup_export`
  - Error if `unseal.key` missing for snapshot; `ErrSealed` for export when sealed

- [ ] **Step 1: Write failing integration tests**

```go
func TestSnapshotRestoreAndExportImport(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "pass")
	v.Put(..., Secret{Name: "openai.api_key", Type: "api_key", Secret: "sk"})
	var buf bytes.Buffer
	if err := v.WriteSnapshot("test", &buf); err != nil { t.Fatal(err) }
	// Extract to destDir via backup.ExtractSnapshotTarGz
	v2, err := vault.Open(destDir)
	v2.TryAutoUnseal(filepath.Join(destDir, "unseal.key"))
	got, err := v2.Get("test", "openai.api_key", true)
	// assert secret

	blob, err := v.BuildExport("test", "backup-pass")
	// OpenExport; assert record
}
```

Also test `BuildExport` while sealed → `ErrSealed`.

- [ ] **Step 2: Run — expect FAIL**

```bash
go test ./internal/vault/ -run 'TestSnapshot|TestExport' -v
```

- [ ] **Step 3: Implement vault backup methods**

Use `os.CreateTemp` in `dataDir` for vacuum target; `chmod 0600`; remove after archive.

- [ ] **Step 4: Run — expect PASS**

```bash
go test ./internal/vault/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/vault
git commit -m "feat(vault): add snapshot write and encrypted export builders"
```

---

### Task 4: HTTP API + client downloads

**Files:**
- Modify: `internal/api/server.go`
- Modify: `internal/api/server_test.go`
- Modify: `internal/client/client.go`
- Modify: `internal/client/client_test.go`

**Interfaces:**
- Consumes: `Vault.WriteSnapshot`, `Vault.BuildExport`
- Produces:
  - `GET /v1/backup/snapshot` → `Content-Type: application/gzip` (or `application/x-gtar`), `Content-Disposition: attachment; filename="agent-vault-snapshot.avs.tar.gz"`
  - `POST /v1/backup/export` JSON `{backup_passphrase}` → `application/octet-stream`, filename `agent-vault-export.ave`
  - Client:
    - `func (c *Client) DownloadSnapshot(w io.Writer) error`
    - `func (c *Client) DownloadExport(backupPassphrase string, w io.Writer) error`
    - `func (c *Client) ImportExportRecords` not needed if import uses Create/Put in CLI — add `ImportSecrets(records []backup.ExportRecord, overwrite bool) (created, skipped, overwritten int, err error)` on client **or** keep import loop in CLI using existing Create/Put. Prefer client helper for reuse/tests.

- [ ] **Step 1: Write API tests**

Bearer required; snapshot 200 with gzip magic; export sealed→503; export with passphrase returns AVE1 magic; wrong/missing auth 401.

- [ ] **Step 2: Implement handlers + client methods**

Stream response with `w.Write`; set headers before write.

- [ ] **Step 3: Run**

```bash
go test ./internal/api/ ./internal/client/ ./internal/vault/ -v
```

- [ ] **Step 4: Commit**

```bash
git add internal/api internal/client
git commit -m "feat(api): add backup snapshot and export download endpoints"
```

---

### Task 5: CLI backup / restore / export / import

**Files:**
- Modify: `cmd/vault/main.go`
- Create: `internal/backup/restore.go` (optional thin helper: `RestoreSnapshotFile(in, dataDir string, force bool) error`)

**Interfaces:**
- `vault backup [--out file]` — API DownloadSnapshot to file (default `agent-vault-YYYYMMDD-HHMMSS.avs.tar.gz`)
- `vault restore --in file --data-dir DIR [--force]` — local extract; refuse if `vault.db` exists without force
- `vault export --passphrase X [--out file]` — API DownloadExport
- `vault import --passphrase X --in file [--overwrite]` — OpenExport locally, then Create/Put via API

Passphrase flags: allow `--passphrase` or prompt with `term.ReadPassword` (no echo). Never print secrets.

- [ ] **Step 1: Implement restore helper + CLI commands with a small package test for restore refuse/force**

```go
func TestRestoreRefusesExistingDB(t *testing.T) { ... }
```

- [ ] **Step 2: Manual/integration via Go test using httptest + CLI helpers if extracted; at minimum test restore helper and rely on Task 6 smoke**

- [ ] **Step 3: Update help text in `cmd/vault/main.go`**

- [ ] **Step 4: `go test ./...` + `go build -o /tmp/vault ./cmd/vault/`**

- [ ] **Step 5: Commit**

```bash
git add cmd/vault internal/backup
git commit -m "feat(cli): add backup, restore, export, and import commands"
```

---

### Task 6: Admin UI downloads + docs + smoke-backup

**Files:**
- Modify: `internal/ui/handlers.go`, `handlers_test.go`
- Modify: `internal/ui/static/app.js`, `app.css`
- Modify: `internal/ui/templates/layout.html` (or list page) — Backup panel with two buttons
- Create: `scripts/smoke-backup.sh`
- Modify: `README.md`, `skills/*/SKILL.md`

**Interfaces:**
- `GET /ui/api/backup/snapshot` (session)
- `POST /ui/api/backup/export` (session+CSRF, JSON passphrase) → file body
- JS: download via fetch blob + `<a download>`; export prompts for backup passphrase
- smoke-backup.sh:
  1. init + server + set secret
  2. CLI backup → restore to other dir → get secret
  3. CLI export → import into second running vault (or same after delete) 
  4. No secret/passphrase/`avt_` in stdout

- [ ] **Step 1: UI handler tests for session download**

- [ ] **Step 2: Wire UI + polish**

- [ ] **Step 3: Write and run smoke-backup.sh**

```bash
chmod +x scripts/smoke-backup.sh
bash scripts/smoke-backup.sh
go test ./...
bash scripts/smoke.sh
bash scripts/smoke-ui.sh
```

- [ ] **Step 4: README section “Backup & export” + skills one-liner**

- [ ] **Step 5: Commit**

```bash
git add internal/ui scripts/smoke-backup.sh README.md skills
git commit -m "feat(ui): add backup downloads and smoke-backup verification"
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| Snapshot format + VacuumInto | 1, 3 |
| Export AVE1 crypto | 2, 3 |
| API downloads | 4 |
| CLI backup/restore/export/import | 5 |
| UI download only | 6 |
| Restore --force / import overwrite | 5, 6 |
| Audit without secrets | 3 |
| Docs + smoke | 6 |
| No HTTPS/cron | Global |

## Plan self-review notes

- `Vault` already has `dataDir` for unseal/root paths — snapshot uses it.
- Import uses API Create/Put (running vault), not raw DB merge.
- Restore is filesystem-only and documented as requiring server stop.
- No placeholders remaining for Phase 2b scope.
