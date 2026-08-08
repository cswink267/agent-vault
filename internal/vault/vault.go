package vault

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cswink267/agent-vault/internal/auth"
	"github.com/cswink267/agent-vault/internal/crypto"
	"github.com/cswink267/agent-vault/internal/security"
	"github.com/cswink267/agent-vault/internal/store"
)

// kdfGate bounds concurrent Argon2 derivations (login/unlock/change).
var kdfGate = security.NewKDFGate(2)

var ErrSealed = errors.New("vault is sealed")
var ErrInvalidMasterKey = errors.New("unseal key does not match this vault")

const (
	masterCheckMetaKey = "master_check"
	masterCheckMessage = "agent-vault-ok"
)

var validTypes = map[string]bool{
	"api_key": true,
	"login":   true,
	"ssh_key": true,
	"token":   true,
	"note":    true,
}

type Vault struct {
	mu             sync.RWMutex
	store          *store.Store
	master         *crypto.MasterKey
	dataDir        string
	caddyConfigDir string
}

type InitResult struct {
	Token        string
	UnsealKeyHex string
}

type Secret struct {
	ID        string
	Name      string
	Type      string
	Username  string
	Secret    string
	URL       string
	Tags      []string
	Notes     string
	Metadata  map[string]string
	CreatedAt string
	UpdatedAt string
	Version   int
}

func Init(dataDir, passphrase string) (*Vault, InitResult, error) {
	if err := security.ValidatePassphrase(passphrase); err != nil {
		return nil, InitResult{}, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, InitResult{}, err
	}

	dbPath := filepath.Join(dataDir, "vault.db")
	if _, err := os.Stat(dbPath); err == nil {
		return nil, InitResult{}, fmt.Errorf("vault already initialized")
	} else if !os.IsNotExist(err) {
		return nil, InitResult{}, err
	}

	st, err := store.Open(dbPath)
	if err != nil {
		return nil, InitResult{}, err
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		st.Close()
		return nil, InitResult{}, err
	}
	master, err := crypto.GenerateMasterKey()
	if err != nil {
		st.Close()
		return nil, InitResult{}, err
	}
	kek, err := deriveKEK(passphrase, salt)
	if err != nil {
		st.Close()
		return nil, InitResult{}, err
	}
	wrapped, err := crypto.WrapKey(master, kek)
	if err != nil {
		st.Close()
		return nil, InitResult{}, err
	}

	if err := st.SetMeta("salt", hex.EncodeToString(salt)); err != nil {
		st.Close()
		return nil, InitResult{}, err
	}
	if err := st.SetMeta("wrapped_master", hex.EncodeToString(wrapped)); err != nil {
		st.Close()
		return nil, InitResult{}, err
	}
	if err := st.SetMeta(masterCheckMetaKey, hex.EncodeToString(masterCheck(master))); err != nil {
		st.Close()
		return nil, InitResult{}, err
	}
	if err := st.SetMeta("initialized", "1"); err != nil {
		st.Close()
		return nil, InitResult{}, err
	}

	unsealKeyHex := hex.EncodeToString(master[:])
	unsealPath := filepath.Join(dataDir, "unseal.key")
	if err := os.WriteFile(unsealPath, []byte(unsealKeyHex), 0o600); err != nil {
		st.Close()
		return nil, InitResult{}, err
	}

	plaintext, hash, err := auth.NewToken()
	if err != nil {
		st.Close()
		return nil, InitResult{}, err
	}
	if _, err := st.CreateToken("root", hash); err != nil {
		st.Close()
		return nil, InitResult{}, err
	}

	rootTokenPath := filepath.Join(dataDir, "root.token")
	if err := os.WriteFile(rootTokenPath, []byte(plaintext), 0o600); err != nil {
		st.Close()
		return nil, InitResult{}, err
	}

	m := master
	v := &Vault{store: st, master: &m, dataDir: dataDir}
	return v, InitResult{Token: plaintext, UnsealKeyHex: unsealKeyHex}, nil
}

func Open(dataDir string) (*Vault, error) {
	dbPath := filepath.Join(dataDir, "vault.db")
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return &Vault{store: st, dataDir: dataDir}, nil
}

func (v *Vault) Sealed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.master == nil
}

func (v *Vault) UnlockWithPassphrase(passphrase string, actorLabel ...string) error {
	master, err := v.unwrapMasterFromPassphrase(passphrase)
	if err != nil {
		return err
	}
	return v.UnlockWithKey(master, actorLabel...)
}

func (v *Vault) VerifyPassphrase(passphrase string) error {
	master, err := v.unwrapMasterFromPassphrase(passphrase)
	if err != nil {
		return err
	}
	return v.verifyMaster(master)
}

func (v *Vault) LoginWithPassphrase(passphrase, actorLabel string) error {
	master, err := v.unwrapMasterFromPassphrase(passphrase)
	if err != nil {
		return err
	}
	if err := v.verifyMaster(master); err != nil {
		return err
	}
	if !v.Sealed() {
		return nil
	}
	return v.UnlockWithKey(master, actorLabel)
}

// ChangePassphrase rewraps the current master key under a new passphrase-derived KEK.
// Requires an unsealed vault. Does not modify unseal.key, secrets, or the in-memory master.
// All bearer tokens are revoked and a fresh root token is minted (returned once).
func (v *Vault) ChangePassphrase(oldPass, newPass, actorLabel string) (string, error) {
	if err := security.ValidatePassphrase(newPass); err != nil {
		return "", err
	}
	if newPass == oldPass {
		return "", errors.New("new passphrase must differ from old passphrase")
	}

	live, err := v.copyMaster()
	if err != nil {
		return "", err
	}

	unwrapped, err := v.unwrapMasterFromPassphrase(oldPass)
	if err != nil {
		return "", ErrInvalidMasterKey
	}
	if subtle.ConstantTimeCompare(unwrapped[:], live[:]) != 1 {
		return "", ErrInvalidMasterKey
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		return "", err
	}
	kek, err := deriveKEK(newPass, salt)
	if err != nil {
		return "", err
	}
	wrapped, err := crypto.WrapKey(live, kek)
	if err != nil {
		return "", err
	}

	if err := v.store.SetMeta("salt", hex.EncodeToString(salt)); err != nil {
		return "", err
	}
	if err := v.store.SetMeta("wrapped_master", hex.EncodeToString(wrapped)); err != nil {
		return "", err
	}

	actor := actorLabel
	if actor == "" {
		actor = "unknown"
	}
	if err := v.store.AppendAudit(actor, "change_passphrase", ""); err != nil {
		return "", err
	}
	return v.revokeTokensAndMintRoot(actor)
}

func (v *Vault) revokeTokensAndMintRoot(actor string) (string, error) {
	if _, err := v.store.DeleteAllTokens(); err != nil {
		return "", err
	}
	if err := v.store.AppendAudit(actor, "revoke_tokens", ""); err != nil {
		return "", err
	}
	plaintext, hash, err := auth.NewToken()
	if err != nil {
		return "", err
	}
	if _, err := v.store.CreateToken("root", hash); err != nil {
		return "", err
	}
	if v.dataDir != "" {
		rootPath := filepath.Join(v.dataDir, "root.token")
		if err := os.WriteFile(rootPath, []byte(plaintext), 0o600); err != nil {
			return "", err
		}
	}
	return plaintext, nil
}

// RotateMasterKey generates a new master key, rewraps all secret DEKs, updates
// unseal.key, and rewraps the master under the current passphrase. Bearer tokens
// are revoked and a fresh root token is returned once.
func (v *Vault) RotateMasterKey(passphrase, actorLabel string) (string, error) {
	if passphrase == "" {
		return "", errors.New("passphrase is required")
	}
	oldMaster, err := v.copyMaster()
	if err != nil {
		return "", err
	}
	unwrapped, err := v.unwrapMasterFromPassphrase(passphrase)
	if err != nil {
		return "", ErrInvalidMasterKey
	}
	if subtle.ConstantTimeCompare(unwrapped[:], oldMaster[:]) != 1 {
		return "", ErrInvalidMasterKey
	}

	newMaster, err := crypto.GenerateMasterKey()
	if err != nil {
		return "", err
	}

	rows, err := v.store.ListSecrets()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	updated := make([]store.SecretRow, len(rows))
	for i, row := range rows {
		secWrap, err := rewrapDEK(oldMaster, newMaster, row.SecretWrappedDEK)
		if err != nil {
			return "", fmt.Errorf("rewrap secret %s: %w", row.Name, err)
		}
		userWrap, err := rewrapDEK(oldMaster, newMaster, row.UsernameWrappedDEK)
		if err != nil {
			return "", fmt.Errorf("rewrap username %s: %w", row.Name, err)
		}
		row.SecretWrappedDEK = secWrap
		row.UsernameWrappedDEK = userWrap
		row.UpdatedAt = now
		row.Version++
		updated[i] = row
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		return "", err
	}
	kek, err := deriveKEK(passphrase, salt)
	if err != nil {
		return "", err
	}
	wrapped, err := crypto.WrapKey(newMaster, kek)
	if err != nil {
		return "", err
	}

	if err := v.store.ApplyMasterRotation(
		updated,
		hex.EncodeToString(salt),
		hex.EncodeToString(wrapped),
		hex.EncodeToString(masterCheck(newMaster)),
	); err != nil {
		return "", err
	}

	if v.dataDir != "" {
		unsealPath := filepath.Join(v.dataDir, "unseal.key")
		if err := os.WriteFile(unsealPath, []byte(hex.EncodeToString(newMaster[:])), 0o600); err != nil {
			return "", err
		}
	}

	v.mu.Lock()
	m := newMaster
	v.master = &m
	v.mu.Unlock()

	actor := actorLabel
	if actor == "" {
		actor = "unknown"
	}
	if err := v.store.AppendAudit(actor, "rotate_master", ""); err != nil {
		return "", err
	}
	token, err := v.revokeTokensAndMintRoot(actor)
	if err != nil {
		return "", err
	}
	return token, nil
}

func rewrapDEK(oldMaster, newMaster crypto.MasterKey, wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 {
		return wrapped, nil
	}
	dek, err := crypto.UnwrapKey(wrapped, oldMaster)
	if err != nil {
		return nil, err
	}
	return crypto.WrapKey(dek, newMaster)
}

func (v *Vault) unwrapMasterFromPassphrase(passphrase string) (crypto.MasterKey, error) {
	saltHex, ok, err := v.store.GetMeta("salt")
	if err != nil {
		return crypto.MasterKey{}, err
	}
	if !ok {
		return crypto.MasterKey{}, errors.New("vault not initialized")
	}
	wrappedHex, ok, err := v.store.GetMeta("wrapped_master")
	if err != nil {
		return crypto.MasterKey{}, err
	}
	if !ok {
		return crypto.MasterKey{}, errors.New("vault not initialized")
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return crypto.MasterKey{}, err
	}
	wrapped, err := hex.DecodeString(wrappedHex)
	if err != nil {
		return crypto.MasterKey{}, err
	}

	kek, err := deriveKEK(passphrase, salt)
	if err != nil {
		return crypto.MasterKey{}, err
	}
	return crypto.UnwrapKey(wrapped, kek)
}

func deriveKEK(passphrase string, salt []byte) (crypto.MasterKey, error) {
	kdfGate.Acquire()
	defer kdfGate.Release()
	return crypto.DeriveKey(passphrase, salt)
}

func (v *Vault) UnlockWithKey(master crypto.MasterKey, actorLabel ...string) error {
	if err := v.verifyMaster(master); err != nil {
		return err
	}
	v.mu.Lock()
	m := master
	v.master = &m
	v.mu.Unlock()
	if actor := optionalActor(actorLabel); actor != "" {
		return v.store.AppendAudit(actor, "unlock", "")
	}
	return nil
}

func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.master = nil
}

func (v *Vault) LockWithAudit(actorLabel string) error {
	v.Lock()
	return v.store.AppendAudit(actorLabel, "lock", "")
}

func (v *Vault) TryAutoUnseal(unsealKeyPath string) (bool, error) {
	data, err := os.ReadFile(unsealKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	keyBytes, err := hex.DecodeString(string(data))
	if err != nil {
		return false, err
	}
	if len(keyBytes) != crypto.MasterKeySize {
		return false, fmt.Errorf("invalid unseal key length")
	}
	var master crypto.MasterKey
	copy(master[:], keyBytes)
	if err := v.UnlockWithKey(master); err != nil {
		return false, err
	}
	return true, nil
}

func (v *Vault) Put(actorLabel string, sec Secret) (Secret, error) {
	if err := validateSecret(sec); err != nil {
		return Secret{}, err
	}

	master, err := v.copyMaster()
	if err != nil {
		return Secret{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)

	existing, err := v.store.GetSecretByName(sec.Name)
	if errors.Is(err, store.ErrNotFound) {
		row, err := buildSecretRow(master, sec, newID(), now, now, 1)
		if err != nil {
			return Secret{}, err
		}
		if err := v.store.CreateSecret(row); err != nil {
			return Secret{}, err
		}
		if err := v.store.AppendAudit(actorLabel, "set", sec.Name); err != nil {
			return Secret{}, err
		}
		return rowToSecret(row, sec.Secret, sec.Username), nil
	}
	if err != nil {
		return Secret{}, err
	}

	row, err := buildSecretRow(master, sec, existing.ID, existing.CreatedAt, now, existing.Version+1)
	if err != nil {
		return Secret{}, err
	}
	if err := v.store.UpdateSecret(row); err != nil {
		return Secret{}, err
	}
	if err := v.store.AppendAudit(actorLabel, "set", sec.Name); err != nil {
		return Secret{}, err
	}
	return rowToSecret(row, sec.Secret, sec.Username), nil
}

func (v *Vault) Create(actorLabel string, sec Secret) (Secret, error) {
	if err := validateSecret(sec); err != nil {
		return Secret{}, err
	}

	master, err := v.copyMaster()
	if err != nil {
		return Secret{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	row, err := buildSecretRow(master, sec, newID(), now, now, 1)
	if err != nil {
		return Secret{}, err
	}
	if err := v.store.CreateSecret(row); err != nil {
		return Secret{}, err
	}
	if err := v.store.AppendAudit(actorLabel, "set", sec.Name); err != nil {
		return Secret{}, err
	}
	return rowToSecret(row, sec.Secret, sec.Username), nil
}

func (v *Vault) Get(actorLabel, name string, reveal bool) (Secret, error) {
	master, err := v.copyMaster()
	if err != nil {
		return Secret{}, err
	}

	row, err := v.store.GetSecretByName(name)
	if err != nil {
		return Secret{}, err
	}

	action := "get"
	if reveal {
		action = "get_reveal"
	}
	if err := v.store.AppendAudit(actorLabel, action, name); err != nil {
		return Secret{}, err
	}

	sec := rowToSecret(row, "", "")
	if !reveal {
		return sec, nil
	}

	secretPT, err := crypto.Open(master, crypto.EncryptedBlob{
		Nonce:      row.SecretNonce,
		Ciphertext: row.SecretCT,
		WrappedDEK: row.SecretWrappedDEK,
	})
	if err != nil {
		return Secret{}, err
	}
	sec.Secret = string(secretPT)

	if len(row.UsernameNonce) > 0 {
		userPT, err := crypto.Open(master, crypto.EncryptedBlob{
			Nonce:      row.UsernameNonce,
			Ciphertext: row.UsernameCT,
			WrappedDEK: row.UsernameWrappedDEK,
		})
		if err != nil {
			return Secret{}, err
		}
		sec.Username = string(userPT)
	}
	return sec, nil
}

func (v *Vault) Delete(actorLabel, name string) error {
	return v.withUnsealed(func() error {
		if err := v.store.DeleteSecret(name); err != nil {
			return err
		}
		return v.store.AppendAudit(actorLabel, "delete", name)
	})
}

func (v *Vault) List(actorLabel string) ([]Secret, error) {
	var out []Secret
	err := v.withUnsealed(func() error {
		rows, err := v.store.ListSecrets()
		if err != nil {
			return err
		}
		out = make([]Secret, len(rows))
		for i, row := range rows {
			out[i] = rowToSecret(row, "", "")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (v *Vault) Search(actorLabel, q, tag, typ string) ([]Secret, error) {
	var out []Secret
	err := v.withUnsealed(func() error {
		rows, err := v.store.SearchSecrets(q, tag, typ)
		if err != nil {
			return err
		}
		out = make([]Secret, len(rows))
		for i, row := range rows {
			out[i] = rowToSecret(row, "", "")
		}
		return v.store.AppendAudit(actorLabel, "search", "")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (v *Vault) CreateToken(actorLabel, label string) (string, error) {
	plaintext, hash, err := auth.NewToken()
	if err != nil {
		return "", err
	}
	if _, err := v.store.CreateToken(label, hash); err != nil {
		return "", err
	}
	return plaintext, nil
}

func (v *Vault) Authenticate(plaintextToken string) (string, bool, error) {
	hash := auth.HashToken(plaintextToken)
	row, ok, err := v.store.FindTokenByHash(hash)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	if !auth.VerifyToken(plaintextToken, row.Hash) {
		return "", false, nil
	}
	return row.Label, true, nil
}

func (v *Vault) ListAudit(limit int) ([]store.AuditRow, error) {
	return v.store.ListAudit(limit)
}

func (v *Vault) copyMaster() (crypto.MasterKey, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.master == nil {
		return crypto.MasterKey{}, ErrSealed
	}
	return *v.master, nil
}

func (v *Vault) withUnsealed(fn func() error) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.master == nil {
		return ErrSealed
	}
	return fn()
}

func validateSecret(sec Secret) error {
	if sec.Name == "" {
		return errors.New("name is required")
	}
	if sec.Secret == "" {
		return errors.New("secret is required")
	}
	if !validTypes[sec.Type] {
		return fmt.Errorf("invalid type: %s", sec.Type)
	}
	return nil
}

func rowToSecret(row store.SecretRow, secret, username string) Secret {
	var tags []string
	_ = json.Unmarshal([]byte(row.TagsJSON), &tags)
	var metadata map[string]string
	_ = json.Unmarshal([]byte(row.MetadataJSON), &metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	return Secret{
		ID:        row.ID,
		Name:      row.Name,
		Type:      row.Type,
		Username:  username,
		Secret:    secret,
		URL:       row.URL,
		Tags:      tags,
		Notes:     row.Notes,
		Metadata:  metadata,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
		Version:   row.Version,
	}
}

func (v *Vault) verifyMaster(master crypto.MasterKey) error {
	checkHex, ok, err := v.store.GetMeta(masterCheckMetaKey)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("vault master check missing")
	}
	check, err := hex.DecodeString(checkHex)
	if err != nil {
		return fmt.Errorf("vault master check invalid: %w", err)
	}
	if !hmac.Equal(masterCheck(master), check) {
		return ErrInvalidMasterKey
	}
	return nil
}

func masterCheck(master crypto.MasterKey) []byte {
	mac := hmac.New(sha256.New, master[:])
	_, _ = mac.Write([]byte(masterCheckMessage))
	return mac.Sum(nil)
}

func optionalActor(actorLabel []string) string {
	if len(actorLabel) == 0 {
		return ""
	}
	return actorLabel[0]
}

func buildSecretRow(master crypto.MasterKey, sec Secret, id, createdAt, updatedAt string, version int) (store.SecretRow, error) {
	secretBlob, err := crypto.Seal(master, []byte(sec.Secret))
	if err != nil {
		return store.SecretRow{}, err
	}

	var usernameNonce, usernameCT, usernameWrapped []byte
	if sec.Username != "" {
		userBlob, err := crypto.Seal(master, []byte(sec.Username))
		if err != nil {
			return store.SecretRow{}, err
		}
		usernameNonce = userBlob.Nonce
		usernameCT = userBlob.Ciphertext
		usernameWrapped = userBlob.WrappedDEK
	}

	tagsJSON, err := json.Marshal(sec.Tags)
	if err != nil {
		return store.SecretRow{}, err
	}
	if sec.Metadata == nil {
		sec.Metadata = map[string]string{}
	}
	metadataJSON, err := json.Marshal(sec.Metadata)
	if err != nil {
		return store.SecretRow{}, err
	}

	return store.SecretRow{
		ID:                 id,
		Name:               sec.Name,
		Type:               sec.Type,
		UsernameNonce:      usernameNonce,
		UsernameCT:         usernameCT,
		UsernameWrappedDEK: usernameWrapped,
		SecretNonce:        secretBlob.Nonce,
		SecretCT:           secretBlob.Ciphertext,
		SecretWrappedDEK:   secretBlob.WrappedDEK,
		URL:                sec.URL,
		TagsJSON:           string(tagsJSON),
		Notes:              sec.Notes,
		MetadataJSON:       string(metadataJSON),
		CreatedAt:          createdAt,
		UpdatedAt:          updatedAt,
		Version:            version,
	}, nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
