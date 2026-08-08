package client_test

import (
	"net/http/httptest"
	"testing"

	"github.com/cswink267/agent-vault/internal/api"
	"github.com/cswink267/agent-vault/internal/client"
	"github.com/cswink267/agent-vault/internal/vault"
)

func setupTestServer(t *testing.T) (*client.Client, func()) {
	t.Helper()
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	c := client.New(ts.URL, res.Token)
	return c, ts.Close
}

func TestPutGetSearch(t *testing.T) {
	c, cleanup := setupTestServer(t)
	defer cleanup()

	sec := vault.Secret{
		Name:   "openai.api_key",
		Type:   "api_key",
		Secret: "sk-test",
		Tags:   []string{"cursor", "claude"},
	}
	out, err := c.Put(sec)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if out.Name != sec.Name {
		t.Fatalf("Put name: %q", out.Name)
	}

	got, err := c.Get(sec.Name, true)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Secret != sec.Secret {
		t.Fatalf("Get secret: %q", got.Secret)
	}

	results, err := c.Search("openai", "", "")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Search results: %d", len(results))
	}
	if results[0].Name != sec.Name {
		t.Fatalf("Search name: %q", results[0].Name)
	}
}

func TestHealthUnlockLockListDeleteAuditCreateToken(t *testing.T) {
	c, cleanup := setupTestServer(t)
	defer cleanup()

	ok, sealed, err := c.Health()
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !ok || sealed {
		t.Fatalf("Health ok=%v sealed=%v", ok, sealed)
	}

	sec := vault.Secret{Name: "k", Type: "api_key", Secret: "v"}
	if _, err := c.Put(sec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	list, err := c.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List len: %d", len(list))
	}

	if err := c.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	_, _, err = c.Health()
	if err != nil {
		t.Fatalf("Health after lock: %v", err)
	}

	if err := c.Unlock("pass"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	if err := c.Delete("k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	rows, err := c.Audit(10)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("Audit: expected rows")
	}

	token, label, err := c.CreateToken("hermes")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if token == "" || label != "hermes" {
		t.Fatalf("CreateToken token=%q label=%q", token, label)
	}
}
