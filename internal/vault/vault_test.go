package vault_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cswink267/agent-vault/internal/crypto"
	"github.com/cswink267/agent-vault/internal/vault"
)

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

func TestUnlockWithWrongUnsealKeyFails(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "test-pass")
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()

	var wrong crypto.MasterKey
	if _, err := rand.Read(wrong[:]); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(wrong[:]) == res.UnsealKeyHex {
		wrong[0] ^= 0xff
	}

	if err := v.UnlockWithKey(wrong); !errors.Is(err, vault.ErrInvalidMasterKey) {
		t.Fatalf("wrong key err = %v, want %v", err, vault.ErrInvalidMasterKey)
	}
	if !v.Sealed() {
		t.Fatal("wrong unseal key must not unseal vault")
	}

	keyBytes, err := hex.DecodeString(res.UnsealKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	var master crypto.MasterKey
	copy(master[:], keyBytes)
	if err := v.UnlockWithKey(master); err != nil {
		t.Fatalf("correct key unlock: %v", err)
	}
	if v.Sealed() {
		t.Fatal("correct unseal key should unseal vault")
	}
}
