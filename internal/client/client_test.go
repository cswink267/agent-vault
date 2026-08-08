package client_test

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/cswink267/agent-vault/internal/api"
	"github.com/cswink267/agent-vault/internal/client"
	"github.com/cswink267/agent-vault/internal/vault"
)

func setupTestServer(t *testing.T) (*client.Client, func()) {
	t.Helper()
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "test-passphrase")
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

func TestDownloadSnapshotAndExport(t *testing.T) {
	c, cleanup := setupTestServer(t)
	defer cleanup()

	sec := vault.Secret{Name: "exp", Type: "api_key", Secret: "val"}
	if _, err := c.Put(sec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var snap bytes.Buffer
	if err := c.DownloadSnapshot("snapshot-passphrase", &snap); err != nil {
		t.Fatalf("DownloadSnapshot: %v", err)
	}
	data := snap.Bytes()
	if len(data) < 4 || string(data[:4]) != "AVS2" {
		t.Fatalf("snapshot missing AVS2 magic")
	}

	var export bytes.Buffer
	if err := c.DownloadExport("backup-passphrase", &export); err != nil {
		t.Fatalf("DownloadExport: %v", err)
	}
	expData := export.Bytes()
	if len(expData) < 4 || string(expData[:4]) != "AVE1" {
		t.Fatalf("export missing AVE1 magic")
	}
}

func TestHealthUnlockLockListDeleteAuditCreateToken(t *testing.T) {
	c, cleanup := setupTestServer(t)
	defer cleanup()

	ok, _, err := c.Health()
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !ok {
		t.Fatalf("Health ok=%v", ok)
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

	if err := c.Unlock("test-passphrase"); err != nil {
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

	token, label, scope, err := c.CreateToken("hermes", "agent")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if token == "" || label != "hermes" || scope != "agent" {
		t.Fatalf("CreateToken token=%q label=%q scope=%q", token, label, scope)
	}
}
