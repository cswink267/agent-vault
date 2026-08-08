package vault

import (
	"crypto/rand"
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
	"github.com/cswink267/agent-vault/internal/store"
)

var ErrSealed = errors.New("vault is sealed")

var validTypes = map[string]bool{
	"api_key": true,
	"login":   true,
	"ssh_key": true,
	"token":   true,
	"note":    true,
}

type Vault struct {
	mu     sync.RWMutex
	store  *store.Store
	master *crypto.MasterKey
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
	kek, err := crypto.DeriveKey(passphrase, salt)
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
	v := &Vault{store: st, master: &m}
	return v, InitResult{Token: plaintext, UnsealKeyHex: unsealKeyHex}, nil
}

func Open(dataDir string) (*Vault, error) {
	dbPath := filepath.Join(dataDir, "vault.db")
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return &Vault{store: st}, nil
}

func (v *Vault) Sealed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.master == nil
}

func (v *Vault) UnlockWithPassphrase(passphrase string) error {
	saltHex, ok, err := v.store.GetMeta("salt")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("vault not initialized")
	}
	wrappedHex, ok, err := v.store.GetMeta("wrapped_master")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("vault not initialized")
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return err
	}
	wrapped, err := hex.DecodeString(wrappedHex)
	if err != nil {
		return err
	}

	kek, err := crypto.DeriveKey(passphrase, salt)
	if err != nil {
		return err
	}
	master, err := crypto.UnwrapKey(wrapped, kek)
	if err != nil {
		return err
	}
	return v.UnlockWithKey(master)
}

func (v *Vault) UnlockWithKey(master crypto.MasterKey) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	m := master
	v.master = &m
	return nil
}

func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.master = nil
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
	if v.Sealed() {
		return Secret{}, ErrSealed
	}
	if err := validateSecret(sec); err != nil {
		return Secret{}, err
	}

	master := v.getMaster()
	now := time.Now().UTC().Format(time.RFC3339)

	secretBlob, err := crypto.Seal(master, []byte(sec.Secret))
	if err != nil {
		return Secret{}, err
	}

	var usernameNonce, usernameCT, usernameWrapped []byte
	if sec.Username != "" {
		userBlob, err := crypto.Seal(master, []byte(sec.Username))
		if err != nil {
			return Secret{}, err
		}
		usernameNonce = userBlob.Nonce
		usernameCT = userBlob.Ciphertext
		usernameWrapped = userBlob.WrappedDEK
	}

	tagsJSON, err := json.Marshal(sec.Tags)
	if err != nil {
		return Secret{}, err
	}
	if sec.Metadata == nil {
		sec.Metadata = map[string]string{}
	}
	metadataJSON, err := json.Marshal(sec.Metadata)
	if err != nil {
		return Secret{}, err
	}

	existing, err := v.store.GetSecretByName(sec.Name)
	if errors.Is(err, store.ErrNotFound) {
		row := store.SecretRow{
			ID:                 newID(),
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
			CreatedAt:          now,
			UpdatedAt:          now,
			Version:            1,
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

	row := store.SecretRow{
		ID:                 existing.ID,
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
		CreatedAt:          existing.CreatedAt,
		UpdatedAt:          now,
		Version:            existing.Version + 1,
	}
	if err := v.store.UpdateSecret(row); err != nil {
		return Secret{}, err
	}
	if err := v.store.AppendAudit(actorLabel, "set", sec.Name); err != nil {
		return Secret{}, err
	}
	return rowToSecret(row, sec.Secret, sec.Username), nil
}

func (v *Vault) Get(actorLabel, name string, reveal bool) (Secret, error) {
	if v.Sealed() {
		return Secret{}, ErrSealed
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

	master := v.getMaster()
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
	if v.Sealed() {
		return ErrSealed
	}
	if err := v.store.DeleteSecret(name); err != nil {
		return err
	}
	return v.store.AppendAudit(actorLabel, "delete", name)
}

func (v *Vault) List(actorLabel string) ([]Secret, error) {
	if v.Sealed() {
		return nil, ErrSealed
	}
	rows, err := v.store.ListSecrets()
	if err != nil {
		return nil, err
	}
	out := make([]Secret, len(rows))
	for i, row := range rows {
		out[i] = rowToSecret(row, "", "")
	}
	return out, nil
}

func (v *Vault) Search(actorLabel, q, tag, typ string) ([]Secret, error) {
	if v.Sealed() {
		return nil, ErrSealed
	}
	rows, err := v.store.SearchSecrets(q, tag, typ)
	if err != nil {
		return nil, err
	}
	out := make([]Secret, len(rows))
	for i, row := range rows {
		out[i] = rowToSecret(row, "", "")
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

func (v *Vault) getMaster() crypto.MasterKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return *v.master
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

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
