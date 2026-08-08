package vault_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
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

func TestVerifyPassphraseAndLogin(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyPassphrase("wrong"); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
	if err := v.VerifyPassphrase("correct-horse"); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.LoginWithPassphrase("correct-horse", "ui"); err != nil {
		t.Fatal(err)
	}
	if v.Sealed() {
		t.Fatal("expected unsealed after login")
	}
	// already unsealed: login still ok
	if err := v.LoginWithPassphrase("correct-horse", "ui"); err != nil {
		t.Fatal(err)
	}
}

func TestChangePassphrase(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "old-pass")
	if err != nil {
		t.Fatal(err)
	}
	oldToken := res.Token
	if _, err := v.Put("root", vault.Secret{Name: "keep.me", Type: "note", Secret: "still-here"}); err != nil {
		t.Fatal(err)
	}
	agentTok, err := v.CreateToken("root", "agent")
	if err != nil {
		t.Fatal(err)
	}

	newRoot, err := v.ChangePassphrase("old-pass", "new-pass", "test")
	if err != nil {
		t.Fatal(err)
	}
	if newRoot == "" || newRoot == oldToken {
		t.Fatalf("expected fresh root token, got %q", newRoot)
	}
	if v.Sealed() {
		t.Fatal("change must leave vault unsealed")
	}

	if _, ok, err := v.Authenticate(oldToken); err != nil || ok {
		t.Fatalf("old root token should be revoked: ok=%v err=%v", ok, err)
	}
	if _, ok, err := v.Authenticate(agentTok); err != nil || ok {
		t.Fatalf("agent token should be revoked: ok=%v err=%v", ok, err)
	}
	if label, ok, err := v.Authenticate(newRoot); err != nil || !ok || label != "root" {
		t.Fatalf("new root auth: label=%q ok=%v err=%v", label, ok, err)
	}
	written, err := os.ReadFile(filepath.Join(dir, "root.token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != newRoot {
		t.Fatalf("root.token mismatch")
	}

	if err := v.VerifyPassphrase("old-pass"); err == nil {
		t.Fatal("old passphrase should fail after change")
	}
	if err := v.VerifyPassphrase("new-pass"); err != nil {
		t.Fatal(err)
	}

	got, err := v.Get("root", "keep.me", true)
	if err != nil || got.Secret != "still-here" {
		t.Fatalf("secret after change: %+v err %v", got, err)
	}

	v.Lock()
	ok, err := v.TryAutoUnseal(filepath.Join(dir, "unseal.key"))
	if err != nil || !ok {
		t.Fatalf("unseal.key should still work: ok=%v err=%v", ok, err)
	}
	if err := v.UnlockWithPassphrase("new-pass"); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.UnlockWithPassphrase("old-pass"); err == nil {
		t.Fatal("old passphrase unlock should fail")
	}

	// wrong old
	v2, _, err := vault.Init(t.TempDir(), "correct")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.ChangePassphrase("wrong", "newer", "test"); !errors.Is(err, vault.ErrInvalidMasterKey) {
		t.Fatalf("wrong old: got %v want %v", err, vault.ErrInvalidMasterKey)
	}

	// sealed
	v2.Lock()
	if _, err := v2.ChangePassphrase("correct", "newer", "test"); !errors.Is(err, vault.ErrSealed) {
		t.Fatalf("sealed: got %v want %v", err, vault.ErrSealed)
	}

	// empty / same
	v3, _, err := vault.Init(t.TempDir(), "same-pass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v3.ChangePassphrase("same-pass", "", "test"); err == nil {
		t.Fatal("empty new should fail")
	}
	if _, err := v3.ChangePassphrase("same-pass", "same-pass", "test"); err == nil {
		t.Fatal("same new should fail")
	}
}

func TestRotateMasterKey(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	oldUnseal, err := os.ReadFile(filepath.Join(dir, "unseal.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("root", vault.Secret{Name: "a.key", Type: "api_key", Secret: "sk-keep", Username: "alice", Tags: []string{"t"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("root", vault.Secret{Name: "b.note", Type: "note", Secret: "plain"}); err != nil {
		t.Fatal(err)
	}

	newToken, err := v.RotateMasterKey("pass", "test")
	if err != nil {
		t.Fatal(err)
	}
	if newToken == "" || newToken == res.Token {
		t.Fatalf("expected fresh root token")
	}
	if _, ok, _ := v.Authenticate(res.Token); ok {
		t.Fatal("old token should be revoked")
	}
	if _, ok, err := v.Authenticate(newToken); err != nil || !ok {
		t.Fatal("new token should work")
	}

	got, err := v.Get("root", "a.key", true)
	if err != nil || got.Secret != "sk-keep" || got.Username != "alice" {
		t.Fatalf("secret after rotate: %+v err %v", got, err)
	}
	got2, err := v.Get("root", "b.note", true)
	if err != nil || got2.Secret != "plain" {
		t.Fatalf("note after rotate: %+v err %v", got2, err)
	}

	newUnseal, err := os.ReadFile(filepath.Join(dir, "unseal.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(newUnseal) == string(oldUnseal) {
		t.Fatal("unseal.key should change after master rotate")
	}

	v.Lock()
	ok, err := v.TryAutoUnseal(filepath.Join(dir, "unseal.key"))
	if err != nil || !ok {
		t.Fatalf("auto-unseal after rotate: ok=%v err=%v", ok, err)
	}
	got3, err := v.Get("root", "a.key", true)
	if err != nil || got3.Secret != "sk-keep" {
		t.Fatalf("after auto-unseal: %+v err %v", got3, err)
	}
	if err := v.UnlockWithPassphrase("pass"); err != nil {
		t.Fatal(err)
	}

	v2, _, err := vault.Init(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.RotateMasterKey("wrong", "test"); !errors.Is(err, vault.ErrInvalidMasterKey) {
		t.Fatalf("wrong pass: %v", err)
	}
	v2.Lock()
	if _, err := v2.RotateMasterKey("x", "test"); !errors.Is(err, vault.ErrSealed) {
		t.Fatalf("sealed: %v", err)
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
