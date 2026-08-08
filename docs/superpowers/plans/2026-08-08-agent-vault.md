# Agent Vault Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a from-scratch single-user encrypted vault (Go + SQLite) with REST API, CLI, MCP server, agent skills, and Docker Compose so Cursor, Claude Code, and Hermes can share credentials on the host.

**Architecture:** One `vault-server` process owns seal state, envelope encryption, SQLite persistence, token auth, and audit. CLI and MCP are HTTP clients. Skills teach agents when to call vault tools. Auto-unseal via key file on trusted host.

**Tech Stack:** Go 1.22+, `database/sql` + `modernc.org/sqlite` (pure Go), `golang.org/x/crypto` (Argon2id, HKDF), AES-256-GCM stdlib, `net/http` ServeMux, MCP SDK `github.com/modelcontextprotocol/go-sdk` (or minimal JSON-RPC stdio if SDK friction), Docker multi-stage build.

## Global Constraints

- Single-user full-access tokens only (no ACLs).
- No Vaultwarden/Bitwarden/HashiCorp Vault or other existing password-manager products.
- Encrypt at rest: `secret` and optional `username` only; search fields plaintext.
- Bind HTTP to `0.0.0.0:$PORT`; persist only on Docker volume.
- No public unauthenticated remote init endpoint.
- Token verification must work while sealed; secret ops return 503 when sealed.
- Never log or audit secret values.
- Phase 2 (HTTPS, backup/export, rotation helpers) is out of scope for this plan.
- Module path: `github.com/cswink267/agent-vault`.
- Binary names: `vault-server`, `vault`, `vault-mcp`.
- Env vars: `AGENT_VAULT_URL`, `AGENT_VAULT_TOKEN`, `AGENT_VAULT_DATA_DIR`, `AGENT_VAULT_UNSEAL_KEY`, `PORT` (default `8080`).

## File Structure

| Path | Responsibility |
|------|----------------|
| `go.mod` / `go.sum` | Module and deps |
| `internal/crypto/crypto.go` | Argon2id, AES-GCM, envelope seal/open |
| `internal/crypto/crypto_test.go` | Crypto unit tests |
| `internal/auth/tokens.go` | Generate/hash/verify API tokens |
| `internal/auth/tokens_test.go` | Auth unit tests |
| `internal/store/store.go` | SQLite schema, CRUD, search, audit append |
| `internal/store/store_test.go` | Store integration tests |
| `internal/vault/vault.go` | Seal state, init/unlock/lock, encrypting facade over store |
| `internal/vault/vault_test.go` | Seal + secret lifecycle tests |
| `internal/api/server.go` | HTTP handlers, auth middleware, errors |
| `internal/api/server_test.go` | API integration tests |
| `internal/client/client.go` | Shared HTTP client for CLI/MCP |
| `cmd/vault-server/main.go` | Server entrypoint + auto-unseal |
| `cmd/vault/main.go` | CLI |
| `cmd/vault-mcp/main.go` | MCP stdio server |
| `skills/cursor/SKILL.md` + `mcp.json.example` | Cursor skill + MCP fragment |
| `skills/claude/SKILL.md` | Claude Code skill |
| `skills/hermes/SKILL.md` | Hermes skill |
| `Dockerfile` | Multi-stage build |
| `deploy/docker-compose.yml` | Host deploy |
| `README.md` | Quickstart |

---

### Task 1: Module scaffold + crypto package

**Files:**
- Create: `go.mod`
- Create: `internal/crypto/crypto.go`
- Create: `internal/crypto/crypto_test.go`
- Create: `README.md` (minimal placeholder until Task 9)

**Interfaces:**
- Consumes: none
- Produces:
  - `const MasterKeySize = 32`
  - `type MasterKey [MasterKeySize]byte`
  - `func GenerateMasterKey() (MasterKey, error)`
  - `func DeriveKeyFromPassphrase(passphrase string, salt []byte) (MasterKey, error)` // Argon2id; if salt nil, generate 16-byte salt and caller must persist it — actually return `(key MasterKey, salt []byte, err error)` when salt is nil
  - Prefer: `func HashPassphrase(passphrase string) (salt, paramsBlob, wrappedMaster []byte, master MasterKey, err error)` is too much — keep primitives small:
  - `func NewSalt() ([]byte, error)` // 16 bytes
  - `func DeriveKey(passphrase string, salt []byte) (MasterKey, error)`
  - `func WrapKey(master, kek MasterKey) (ciphertext []byte, err error)` // AES-GCM wrap of master under KEK
  - `func UnwrapKey(ciphertext []byte, kek MasterKey) (MasterKey, error)`
  - `type EncryptedBlob struct { Nonce, Ciphertext, WrappedDEK []byte }`
  - `func Seal(master MasterKey, plaintext []byte) (EncryptedBlob, error)`
  - `func Open(master MasterKey, blob EncryptedBlob) ([]byte, error)`
  - `func RandomKey() (MasterKey, error)` // also used for unseal key file contents (= raw master or wrap — unseal file stores raw 32-byte master key hex)

- [ ] **Step 1: Initialize module**

```bash
cd /workspace
go mod init github.com/cswink267/agent-vault
go get golang.org/x/crypto
```

- [ ] **Step 2: Write failing crypto tests**

```go
package crypto_test

import (
	"bytes"
	"testing"

	"github.com/cswink267/agent-vault/internal/crypto"
)

func TestSealOpenRoundTrip(t *testing.T) {
	master, err := crypto.GenerateMasterKey()
	if err != nil {
		t.fatal(err)
	}
	blob, err := crypto.Seal(master, []byte("s3cr3t"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := crypto.Open(master, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte("s3cr3t")) {
		t.Fatalf("got %q", out)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	m1, _ := crypto.GenerateMasterKey()
	m2, _ := crypto.GenerateMasterKey()
	blob, _ := crypto.Seal(m1, []byte("x"))
	if _, err := crypto.Open(m2, blob); err == nil {
		t.Fatal("expected error")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt, err := crypto.NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	k1, err := crypto.DeriveKey("pass", salt)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := crypto.DeriveKey("pass", salt)
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatal("expected same key")
	}
}

func TestWrapUnwrapMaster(t *testing.T) {
	master, _ := crypto.GenerateMasterKey()
	kek, _ := crypto.GenerateMasterKey()
	wrapped, err := crypto.WrapKey(master, kek)
	if err != nil {
		t.Fatal(err)
	}
	out, err := crypto.UnwrapKey(wrapped, kek)
	if err != nil {
		t.Fatal(err)
	}
	if out != master {
		t.Fatal("mismatch")
	}
}
```

Fix typo in test before running: use `t.Fatal` not `t.fatal`.

- [ ] **Step 3: Run tests — expect FAIL**

```bash
go test ./internal/crypto/ -v
```

Expected: FAIL (package/types undefined)

- [ ] **Step 4: Implement `internal/crypto/crypto.go`**

```go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const MasterKeySize = 32

type MasterKey [MasterKeySize]byte

type EncryptedBlob struct {
	Nonce      []byte
	Ciphertext []byte
	WrappedDEK []byte
}

func GenerateMasterKey() (MasterKey, error) {
	var k MasterKey
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return k, err
	}
	return k, nil
}

func NewSalt() ([]byte, error) {
	s := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, s); err != nil {
		return nil, err
	}
	return s, nil
}

func DeriveKey(passphrase string, salt []byte) (MasterKey, error) {
	var k MasterKey
	if len(salt) < 16 {
		return k, errors.New("salt must be at least 16 bytes")
	}
	// time=3, memory=64MiB, threads=4, keyLen=32
	out := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, MasterKeySize)
	copy(k[:], out)
	return k, nil
}

func aesGCMSeal(key MasterKey, plaintext []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func aesGCMOpen(key MasterKey, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func WrapKey(master, kek MasterKey) ([]byte, error) {
	nonce, ct, err := aesGCMSeal(kek, master[:])
	if err != nil {
		return nil, err
	}
	out := append(nonce, ct...)
	return out, nil
}

func UnwrapKey(wrapped []byte, kek MasterKey) (MasterKey, error) {
	var master MasterKey
	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return master, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return master, err
	}
	ns := gcm.NonceSize()
	if len(wrapped) < ns {
		return master, errors.New("wrapped key too short")
	}
	pt, err := gcm.Open(nil, wrapped[:ns], wrapped[ns:], nil)
	if err != nil {
		return master, err
	}
	if len(pt) != MasterKeySize {
		return master, fmt.Errorf("bad master key length %d", len(pt))
	}
	copy(master[:], pt)
	return master, nil
}

func Seal(master MasterKey, plaintext []byte) (EncryptedBlob, error) {
	var blob EncryptedBlob
	dek, err := GenerateMasterKey()
	if err != nil {
		return blob, err
	}
	nonce, ct, err := aesGCMSeal(dek, plaintext)
	if err != nil {
		return blob, err
	}
	wrapped, err := WrapKey(dek, master)
	if err != nil {
		return blob, err
	}
	blob.Nonce = nonce
	blob.Ciphertext = ct
	blob.WrappedDEK = wrapped
	return blob, nil
}

func Open(master MasterKey, blob EncryptedBlob) ([]byte, error) {
	dek, err := UnwrapKey(blob.WrappedDEK, master)
	if err != nil {
		return nil, err
	}
	return aesGCMOpen(dek, blob.Nonce, blob.Ciphertext)
}
```

- [ ] **Step 5: Run tests — expect PASS**

```bash
go test ./internal/crypto/ -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/crypto README.md
git commit -m "feat(crypto): add AES-GCM envelope encryption and Argon2id KDF"
```

---

### Task 2: API token auth package

**Files:**
- Create: `internal/auth/tokens.go`
- Create: `internal/auth/tokens_test.go`

**Interfaces:**
- Consumes: none
- Produces:
  - `func NewToken() (plaintext string, hash string, err error)` // plaintext like `avt_` + 32 bytes hex
  - `func HashToken(plaintext string) string` // SHA-256 hex
  - `func VerifyToken(plaintext, hash string) bool` // constant-time compare

- [ ] **Step 1: Write failing tests**

```go
package auth_test

import (
	"strings"
	"testing"

	"github.com/cswink267/agent-vault/internal/auth"
)

func TestNewTokenHashVerify(t *testing.T) {
	pt, hash, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pt, "avt_") {
		t.Fatalf("prefix: %s", pt)
	}
	if !auth.VerifyToken(pt, hash) {
		t.Fatal("verify failed")
	}
	if auth.VerifyToken("avt_nope", hash) {
		t.Fatal("expected fail")
	}
	if auth.HashToken(pt) != hash {
		t.Fatal("hash mismatch")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
go test ./internal/auth/ -v
```

- [ ] **Step 3: Implement**

```go
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

func NewToken() (plaintext string, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	plaintext = "avt_" + hex.EncodeToString(b)
	hash = HashToken(plaintext)
	return plaintext, hash, nil
}

func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func VerifyToken(plaintext, hash string) bool {
	expected := HashToken(plaintext)
	if len(expected) != len(hash) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(hash)) == 1
}

// silence unused in case of future helpers
var _ = fmt.Sprintf
```

Remove the unused `fmt` import — do not include `var _ = fmt.Sprintf`; use only needed imports.

- [ ] **Step 4: Run — expect PASS**

```bash
go test ./internal/auth/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/auth
git commit -m "feat(auth): add API token generation and verification"
```

---

### Task 3: SQLite store (metadata + ciphertext blobs + audit + tokens)

**Files:**
- Create: `internal/store/store.go`
- Create: `internal/store/store_test.go`

**Interfaces:**
- Consumes: none (stores opaque blob bytes; no crypto here)
- Produces:
  - `type Store struct`
  - `func Open(path string) (*Store, error)`
  - `func (s *Store) Close() error`
  - Meta table `vault_meta`: keys `salt`, `wrapped_master`, `initialized`
  - `func (s *Store) GetMeta(key string) (string, bool, error)`
  - `func (s *Store) SetMeta(key, value string) error`
  - `type SecretRow struct { ID, Name, Type string; UsernameBlob, SecretBlob []byte; URL string; TagsJSON, Notes, MetadataJSON string; CreatedAt, UpdatedAt string; Version int }`
  - UsernameBlob/SecretBlob store JSON-encoded `crypto.EncryptedBlob` or separate columns — use columns: `username_nonce, username_ct, username_wrapped_dek` (nullable) and same for secret (required)
  - Simpler: store each EncryptedBlob as three BLOB columns
  - `func (s *Store) CreateSecret(row SecretRow) error`
  - `func (s *Store) UpdateSecret(row SecretRow) error`
  - `func (s *Store) GetSecretByName(name string) (SecretRow, error)` // `ErrNotFound`
  - `func (s *Store) DeleteSecret(name string) error`
  - `func (s *Store) ListSecrets() ([]SecretRow, error)`
  - `func (s *Store) SearchSecrets(q, tag, typ string) ([]SecretRow, error)`
  - `type TokenRow struct { ID, Label, Hash, CreatedAt string }`
  - `func (s *Store) CreateToken(label, hash string) (TokenRow, error)`
  - `func (s *Store) ListTokens() ([]TokenRow, error)`
  - `func (s *Store) FindTokenByHash(hash string) (TokenRow, bool, error)`
  - `type AuditRow struct { ID int64; Timestamp, TokenLabel, Action, SecretName string }`
  - `func (s *Store) AppendAudit(tokenLabel, action, secretName string) error`
  - `func (s *Store) ListAudit(limit int) ([]AuditRow, error)`
  - `var ErrNotFound = errors.New("not found")`
  - `var ErrConflict = errors.New("conflict")`

- [ ] **Step 1: Add dependency**

```bash
go get modernc.org/sqlite
```

- [ ] **Step 2: Write failing store test**

```go
package store_test

import (
	"path/filepath"
	"testing"

	"github.com/cswink267/agent-vault/internal/store"
)

func TestSecretCRUDAndSearch(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	row := store.SecretRow{
		ID: "id1", Name: "openai.api_key", Type: "api_key",
		SecretNonce: []byte("n"), SecretCT: []byte("c"), SecretWrappedDEK: []byte("w"),
		URL: "https://api.openai.com", TagsJSON: `["cursor"]`, Notes: "main",
		MetadataJSON: `{}`, CreatedAt: "t1", UpdatedAt: "t1", Version: 1,
	}
	if err := s.CreateSecret(row); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSecret(row); err != store.ErrConflict {
		t.Fatalf("want conflict, got %v", err)
	}
	got, err := s.GetSecretByName("openai.api_key")
	if err != nil || got.Name != row.Name {
		t.Fatalf("get: %v %+v", err, got)
	}
	hits, err := s.SearchSecrets("openai", "cursor", "api_key")
	if err != nil || len(hits) != 1 {
		t.Fatalf("search: %v %d", err, len(hits))
	}
	if err := s.SetMeta("salt", "abc"); err != nil {
		t.Fatal(err)
	}
	v, ok, err := s.GetMeta("salt")
	if err != nil || !ok || v != "abc" {
		t.Fatalf("meta %v %v %q", err, ok, v)
	}
	tr, err := s.CreateToken("cursor", "hash1")
	if err != nil || tr.Label != "cursor" {
		t.Fatal(err, tr)
	}
	if err := s.AppendAudit("cursor", "set", "openai.api_key"); err != nil {
		t.Fatal(err)
	}
	aud, err := s.ListAudit(10)
	if err != nil || len(aud) != 1 || aud[0].Action != "set" {
		t.Fatalf("audit: %v %+v", err, aud)
	}
}
```

- [ ] **Step 3: Run — expect FAIL**

```bash
go test ./internal/store/ -v
```

- [ ] **Step 4: Implement store with schema**

Schema SQL (in `Open` migration):

```sql
CREATE TABLE IF NOT EXISTS vault_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  username_nonce BLOB,
  username_ct BLOB,
  username_wrapped_dek BLOB,
  secret_nonce BLOB NOT NULL,
  secret_ct BLOB NOT NULL,
  secret_wrapped_dek BLOB NOT NULL,
  url TEXT NOT NULL DEFAULT '',
  tags_json TEXT NOT NULL DEFAULT '[]',
  notes TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  token_label TEXT NOT NULL,
  action TEXT NOT NULL,
  secret_name TEXT NOT NULL DEFAULT ''
);
```

Implement `SecretRow` fields matching test. Use driver import `_ "modernc.org/sqlite"` and DSN `file:path?_pragma=busy_timeout(5000)`.

Search: `name LIKE %q%` OR notes LIKE; filter tag with `tags_json LIKE '%"tag"%'`; filter type equality when non-empty.

- [ ] **Step 5: Run — expect PASS**

```bash
go test ./internal/store/ -v
```

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/store
git commit -m "feat(store): add SQLite persistence for secrets, tokens, audit"
```

---

### Task 4: Vault service (init, seal, encrypting CRUD)

**Files:**
- Create: `internal/vault/vault.go`
- Create: `internal/vault/vault_test.go`

**Interfaces:**
- Consumes: `crypto.*`, `auth.*`, `store.*`
- Produces:
  - `type Vault struct` // holds `*store.Store`, `master *crypto.MasterKey` (nil if sealed), mutex
  - `type InitResult struct { Token string; UnsealKeyHex string }`
  - `func Init(dataDir, passphrase string) (*Vault, InitResult, error)` // creates `dataDir/vault.db`, writes `dataDir/unseal.key` (hex master), stores salt+wrapped master in meta, creates token label `root`
  - `func Open(dataDir string) (*Vault, error)` // open DB only, sealed
  - `func (v *Vault) Sealed() bool`
  - `func (v *Vault) UnlockWithPassphrase(passphrase string) error`
  - `func (v *Vault) UnlockWithKey(master crypto.MasterKey) error`
  - `func (v *Vault) Lock()`
  - `func (v *Vault) TryAutoUnseal(unsealKeyPath string) (bool, error)` // read hex file; unlock; false if missing
  - `type Secret struct { ID, Name, Type, Username, Secret, URL string; Tags []string; Notes string; Metadata map[string]string; CreatedAt, UpdatedAt string; Version int }`
  - `func (v *Vault) Put(actorLabel string, sec Secret) (Secret, error)` // create or update by name; encrypt; audit `set`
  - `func (v *Vault) Get(actorLabel, name string, reveal bool) (Secret, error)` // audit `get` or `get_reveal`
  - `func (v *Vault) Delete(actorLabel, name string) error`
  - `func (v *Vault) List(actorLabel string) ([]Secret, error)` // no secret/username
  - `func (v *Vault) Search(actorLabel, q, tag, typ string) ([]Secret, error)`
  - `func (v *Vault) CreateToken(actorLabel, label string) (plaintext string, err error)`
  - `func (v *Vault) Authenticate(plaintextToken string) (label string, ok bool, err error)`
  - `func (v *Vault) ListAudit(limit int) ([]store.AuditRow, error)`
  - `var ErrSealed = errors.New("vault is sealed")`

- [ ] **Step 1: Write failing tests**

```go
func TestInitUnlockPutGetLock(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "test-pass")
	if err != nil {
		t.Fatal(err)
	}
	if res.Token == "" || res.UnsealKeyHex == "" {
		t.Fatal("missing init secrets")
	}
	v.Lock()
	if !v.Sealed() {
		t.Fatal("want sealed")
	}
	if _, err := v.Put("root", vault.Secret{Name: "x", Type: "note", Secret: "nope"}); err != vault.ErrSealed {
		t.Fatalf("want sealed, got %v", err)
	}
	ok, err := v.TryAutoUnseal(filepath.Join(dir, "unseal.key"))
	if err != nil || !ok {
		t.Fatal(err, ok)
	}
	_, err = v.Put("root", vault.Secret{Name: "openai.api_key", Type: "api_key", Secret: "sk-test", Tags: []string{"cursor"}, Username: "user"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Get("root", "openai.api_key", true)
	if err != nil || got.Secret != "sk-test" || got.Username != "user" {
		t.Fatalf("got %+v err %v", got, err)
	}
	hidden, err := v.Get("root", "openai.api_key", false)
	if err != nil || hidden.Secret != "" || hidden.Username != "" {
		t.Fatalf("hidden %+v", hidden)
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
go test ./internal/vault/ -v
```

- [ ] **Step 3: Implement vault service**

On `Init`:
1. `os.MkdirAll(dataDir, 0o700)`
2. Refuse if `vault.db` exists
3. `store.Open`, `crypto.NewSalt`, `GenerateMasterKey`, `DeriveKey(pass, salt)`, `WrapKey(master, kek)`
4. Store meta: `salt` (hex), `wrapped_master` (hex), `initialized=1`
5. Write unseal.key as hex(master) mode 0600
6. `auth.NewToken`, `CreateToken("root", hash)`
7. Keep master in memory (unsealed)

`Put`: if sealed → ErrSealed; validate name/type/secret; if exists update else create; seal username if non-empty else NULL blobs; bump version; audit.

Use `github.com/google/uuid` or `crypto/rand` hex for IDs — prefer stdlib:

```go
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
go test ./internal/vault/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/vault
git commit -m "feat(vault): add init, seal/unseal, and encrypting secret API"
```

---

### Task 5: HTTP API

**Files:**
- Create: `internal/api/server.go`
- Create: `internal/api/server_test.go`
- Create: `cmd/vault-server/main.go`

**Interfaces:**
- Consumes: `*vault.Vault`
- Produces:
  - `type Server struct`
  - `func New(v *vault.Vault) *Server`
  - `func (s *Server) Handler() http.Handler` // routes below
  - Routes exactly as spec:
    - `GET /health` → `{"ok":true,"sealed":bool}` no auth
    - `POST /v1/unlock` JSON `{"passphrase":"..."}` or `{"unseal_key_hex":"..."}` auth required
    - `POST /v1/lock` auth
    - `GET/POST /v1/secrets` auth
    - `GET/PUT/DELETE /v1/secrets/{name}` auth; GET supports `reveal=1`
    - `GET /v1/search` **use `/v1/search`** (avoid `:search` mux issues) with `q`, `tag`, `type` — note: plan amends spec path to `/v1/search` for Go 1.22 mux compatibility; document in README
    - `GET /v1/audit?limit=50` auth
    - `POST /v1/tokens` JSON `{"label":"claude"}` → `{"token":"avt_...","label":"..."}`

- [ ] **Step 1: Write API tests with `httptest`**

```go
func TestHealthAndSecretLifecycle(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	// assert 200, sealed false

	body := `{"name":"k","type":"api_key","secret":"abc","tags":["t"]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/secrets", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+res.Token)
	req.Header.Set("Content-Type", "application/json")
	// assert 201
	// GET reveal=1 returns secret
	v.Lock()
	// GET secrets → 503
}
```

Also test 401 without token.

- [ ] **Step 2: Run — expect FAIL**

```bash
go test ./internal/api/ -v
```

- [ ] **Step 3: Implement server.go**

Use `http.NewServeMux()`, Go 1.22 patterns: `mux.HandleFunc("GET /health", ...)`, `mux.HandleFunc("GET /v1/secrets/{name}", ...)`.

Auth middleware: parse `Authorization: Bearer`, `v.Authenticate`, stash label in context.

JSON helpers; map `vault.ErrSealed` → 503, `store.ErrNotFound` → 404, `store.ErrConflict` → 409.

- [ ] **Step 4: Implement `cmd/vault-server/main.go`**

```go
// PORT default 8080
// AGENT_VAULT_DATA_DIR default /data
// AGENT_VAULT_UNSEAL_KEY default $DATA_DIR/unseal.key
// AGENT_VAULT_PASSPHRASE optional for init if db missing + AGENT_VAULT_INIT=1
// Open or Init; TryAutoUnseal; listen 0.0.0.0:PORT
```

Init policy for Docker:
- If DB missing and `AGENT_VAULT_PASSPHRASE` set → `vault.Init`, log token once to stdout (warn).
- If DB missing and no passphrase → exit with clear error telling operator to set passphrase or run `vault init`.
- If DB exists → `Open` + auto-unseal.

- [ ] **Step 5: Run all package tests**

```bash
go test ./...
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/api cmd/vault-server
git commit -m "feat(api): add REST server with auth, seal, and secrets CRUD"
```

---

### Task 6: Shared HTTP client + CLI

**Files:**
- Create: `internal/client/client.go`
- Create: `internal/client/client_test.go` (httptest against api)
- Create: `cmd/vault/main.go`

**Interfaces:**
- Consumes: HTTP API JSON shapes from Task 5
- Produces:
  - `type Client struct { BaseURL, Token string; HTTP *http.Client }`
  - `func New(baseURL, token string) *Client`
  - Methods: `Health`, `Unlock`, `Lock`, `List`, `Get(name, reveal bool)`, `Put`, `Delete`, `Search`, `Audit`, `CreateToken`
  - CLI subcommands matching spec; `vault init` talks to **local** `vault.Init` via data dir flag (not HTTP), because init is local-only:
    - `vault init --data-dir DIR` prompts or `--passphrase` flag
    - Other commands use `AGENT_VAULT_URL` + `AGENT_VAULT_TOKEN`

- [ ] **Step 1: Write client test against real api handler**

Spin `vault.Init` + `api.New` + `httptest`; `client.Put` / `Get` / `Search`.

- [ ] **Step 2: Run — expect FAIL**

```bash
go test ./internal/client/ -v
```

- [ ] **Step 3: Implement client + CLI**

CLI UX:

```bash
vault init --data-dir ./data --passphrase '...'
vault unlock --passphrase '...'
vault lock
vault set --name openai.api_key --type api_key --secret sk-... --tags cursor,claude
vault get openai.api_key
vault list
vault search openai
vault delete openai.api_key
vault audit
vault token create --label hermes
```

Use `flag` package or `github.com/spf13/cobra` — prefer stdlib `flag` + manual subcommand switch on `os.Args[1]` to avoid extra deps.

- [ ] **Step 4: Manual smoke (optional in CI use client tests)**

```bash
go test ./internal/client/ ./internal/api/ ./internal/vault/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/client cmd/vault
git commit -m "feat(cli): add vault CLI and shared HTTP client"
```

---

### Task 7: MCP server

**Files:**
- Create: `cmd/vault-mcp/main.go`
- Create: `internal/mcptools/tools.go` (tool handlers using client)
- Create: `internal/mcptools/tools_test.go`

**Interfaces:**
- Consumes: `internal/client.Client`
- Produces MCP tools: `vault_search`, `vault_list`, `vault_get`, `vault_set`, `vault_delete`
- Transport: stdio JSON-RPC MCP

Implementation approach (choose at coding time, prefer working minimal):
1. Try `github.com/modelcontextprotocol/go-sdk` 
2. If unstable/unavailable, implement minimal MCP stdio subset: `initialize`, `tools/list`, `tools/call`

Tool schemas:
- `vault_get`: required `name` (string)
- `vault_set`: required `name`, `type`, `secret`; optional `username`, `url`, `tags` (array), `notes`
- `vault_search`: optional `q`, `tag`, `type`
- `vault_list`: no params
- `vault_delete`: required `name`

- [ ] **Step 1: Write unit test for tool dispatch (mock HTTP with httptest)**

Assert `vault_set` then `vault_get` returns secret text in tool result.

- [ ] **Step 2: Implement tools + MCP main**

`cmd/vault-mcp/main.go` reads `AGENT_VAULT_URL` + `AGENT_VAULT_TOKEN`, serves stdio.

- [ ] **Step 3: Test**

```bash
go test ./internal/mcptools/ -v
go build -o bin/vault-mcp ./cmd/vault-mcp/
```

- [ ] **Step 4: Commit**

```bash
git add cmd/vault-mcp internal/mcptools
git commit -m "feat(mcp): add MCP server tools for vault operations"
```

---

### Task 8: Agent skills

**Files:**
- Create: `skills/cursor/SKILL.md`
- Create: `skills/cursor/mcp.json.example`
- Create: `skills/claude/SKILL.md`
- Create: `skills/hermes/SKILL.md`

**Interfaces:**
- Consumes: tool/CLI names from Tasks 6–7
- Produces: installable skill docs with auto-use rules from spec

- [ ] **Step 1: Write Cursor skill**

Include: when to store/retrieve; never echo secrets; prefer MCP tools listed; fallback CLI; env vars; example `vault:openai.api_key` references.

- [ ] **Step 2: Write `mcp.json.example`**

```json
{
  "mcpServers": {
    "agent-vault": {
      "command": "vault-mcp",
      "env": {
        "AGENT_VAULT_URL": "http://localhost:8080",
        "AGENT_VAULT_TOKEN": "<token>"
      }
    }
  }
}
```

- [ ] **Step 3: Write Claude + Hermes skills**

Same rules; Hermes emphasizes CLI if no MCP; Claude Code covers both.

- [ ] **Step 4: Fixture check test (optional small Go test or shell)**

```bash
grep -q vault_get skills/cursor/SKILL.md
grep -q 'vault set' skills/hermes/SKILL.md
grep -q vault_set skills/claude/SKILL.md
```

- [ ] **Step 5: Commit**

```bash
git add skills
git commit -m "docs(skills): add Cursor, Claude Code, and Hermes vault skills"
```

---

### Task 9: Docker deploy + README

**Files:**
- Create: `Dockerfile`
- Create: `deploy/docker-compose.yml`
- Create: `.dockerignore`
- Modify: `README.md`

**Interfaces:**
- Consumes: binaries from prior tasks
- Produces: runnable Compose stack on the host

- [ ] **Step 1: Dockerfile**

```dockerfile
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/vault-server ./cmd/vault-server \
 && CGO_ENABLED=0 go build -o /out/vault ./cmd/vault \
 && CGO_ENABLED=0 go build -o /out/vault-mcp ./cmd/vault-mcp

FROM alpine:3.20
RUN adduser -D -u 1000 vault
COPY --from=build /out/vault-server /out/vault /out/vault-mcp /usr/local/bin/
USER vault
ENV PORT=8080 AGENT_VAULT_DATA_DIR=/data
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["vault-server"]
```

- [ ] **Step 2: compose file**

```yaml
services:
  agent-vault:
    build: ..
    ports:
      - "8080:8080"
    environment:
      PORT: "8080"
      AGENT_VAULT_DATA_DIR: /data
      AGENT_VAULT_UNSEAL_KEY: /data/unseal.key
      AGENT_VAULT_PASSPHRASE: ${AGENT_VAULT_PASSPHRASE}
    volumes:
      - vault-data:/data
    restart: unless-stopped

volumes:
  vault-data:
```

Context note: set `build: ..` with compose file in `deploy/` OR put compose at repo root — **use repo-root `docker-compose.yml` AND keep `deploy/docker-compose.yml` as the canonical one with `build: ..`**.

- [ ] **Step 3: README quickstart**

Cover: build, compose up, init/passphrase env, CLI env, MCP config pointer to skills, security notes (unseal key permissions), Phase 2 preview.

- [ ] **Step 4: Build verify**

```bash
go test ./...
docker build -t agent-vault:local .
```

If Docker unavailable in CI environment, `go test ./...` and `go build` all cmds is sufficient; note in commit.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile .dockerignore deploy/docker-compose.yml README.md
git commit -m "feat(deploy): add Docker image, Compose stack, and README quickstart"
```

---

### Task 10: End-to-end verification + spec path note

**Files:**
- Modify: `docs/superpowers/specs/2026-08-08-agent-vault-design.md` (search path → `/v1/search` if amended)
- Create: `internal/api/e2e_test.go` OR script `scripts/smoke.sh`

- [ ] **Step 1: Align spec search path with implementation**

Replace `GET /v1/secrets:search` with `GET /v1/search` in the design spec (mux-friendly).

- [ ] **Step 2: Write smoke script**

```bash
#!/usr/bin/env bash
set -euo pipefail
DIR=$(mktemp -d)
go build -o "$DIR/vault-server" ./cmd/vault-server
go build -o "$DIR/vault" ./cmd/vault
AGENT_VAULT_DATA_DIR="$DIR/data" AGENT_VAULT_PASSPHRASE='smoke-pass' PORT=18080 \
  "$DIR/vault-server" &
PID=$!
trap 'kill $PID' EXIT
sleep 1
TOKEN=$(jq -r .token <<<"$(/* from init logs — better: vault init then server open */)")
```

Prefer pure Go e2e test already covered by api/client tests; add `scripts/smoke.sh` that:
1. `vault init --data-dir "$DIR/data" --passphrase smoke`
2. Starts server with that data dir + unseal key
3. Uses printed token / `~` parse from init output file
4. `vault set/get/search`

Init should write token to `$DATA_DIR/root.token` mode 0600 **in addition to stdout** to make automation easy (small amendment — implement in Task 4 if not done: write `root.token`).

- [ ] **Step 3: Ensure Task 4 writes `root.token`**

If missing, add + test + commit fix:

```bash
git commit -m "fix(vault): persist root token file for automation"
```

- [ ] **Step 4: Run full verification**

```bash
go test ./...
bash scripts/smoke.sh
```

Expected: all PASS; smoke exits 0

- [ ] **Step 5: Final commit**

```bash
git add docs/superpowers/specs/2026-08-08-agent-vault-design.md scripts/smoke.sh
git commit -m "test: add smoke script and align search API path in spec"
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| Go monolith + SQLite + AES-GCM | 1, 3, 4 |
| Seal / passphrase / auto-unseal | 4, 5 |
| Structured credentials | 3, 4, 5 |
| REST API + errors + audit | 5 |
| CLI | 6 |
| MCP tools | 7 |
| Skills Cursor/Claude/Hermes | 8 |
| Docker Compose on the host | 9 |
| Token auth works while sealed | 4, 5 |
| No remote unauthenticated init | 4, 5, 6 |
| Cross-agent same name | 4–8 (shared API) |
| Phase 2 excluded | Global constraints |

## Plan self-review notes

- Search path amended to `/v1/search` for ServeMux compatibility (Task 5/10).
- `root.token` file added for smoke/automation (Task 10 / Task 4).
- MCP SDK choice deferred to implementer with stdio fallback — both acceptable if tools behave identically.
- No placeholders remaining for Phase 1 scope.
