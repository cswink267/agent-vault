package vault_test

import (
	"path/filepath"
	"testing"

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
