package mcptools_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cswink267/agent-vault/internal/api"
	"github.com/cswink267/agent-vault/internal/client"
	"github.com/cswink267/agent-vault/internal/mcptools"
	"github.com/cswink267/agent-vault/internal/vault"
)

func setupTestTools(t *testing.T) *mcptools.Tools {
	t.Helper()
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	c := client.New(ts.URL, res.Token)
	return mcptools.New(c)
}

func resultText(t *testing.T, result *mcptools.ToolResult) string {
	t.Helper()
	if result == nil {
		t.Fatal("nil result")
	}
	if result.IsError {
		t.Fatalf("tool error: %s", result.Text)
	}
	return result.Text
}

func TestVaultSetThenGet(t *testing.T) {
	tools := setupTestTools(t)

	setResult, err := tools.Dispatch("vault_set", map[string]any{
		"name":   "openai.api_key",
		"type":   "api_key",
		"secret": "sk-test-secret",
		"tags":   []any{"cursor", "claude"},
	})
	if err != nil {
		t.Fatalf("vault_set dispatch: %v", err)
	}
	if setResult.IsError {
		t.Fatalf("vault_set: %s", setResult.Text)
	}

	getResult, err := tools.Dispatch("vault_get", map[string]any{
		"name": "openai.api_key",
	})
	if err != nil {
		t.Fatalf("vault_get dispatch: %v", err)
	}
	text := resultText(t, getResult)
	if !strings.Contains(text, "sk-test-secret") {
		t.Fatalf("vault_get result missing secret: %q", text)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("vault_get JSON: %v", err)
	}
	if payload["secret"] != "sk-test-secret" {
		t.Fatalf("secret field: %v", payload["secret"])
	}
}

func TestVaultListSearchDelete(t *testing.T) {
	tools := setupTestTools(t)

	_, err := tools.Dispatch("vault_set", map[string]any{
		"name":   "db.login",
		"type":   "login",
		"secret": "pw",
		"tags":   []any{"prod"},
	})
	if err != nil {
		t.Fatal(err)
	}

	listResult, err := tools.Dispatch("vault_list", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resultText(t, listResult), "db.login") {
		t.Fatalf("vault_list: %q", listResult.Text)
	}

	searchResult, err := tools.Dispatch("vault_search", map[string]any{
		"tag": "prod",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resultText(t, searchResult), "db.login") {
		t.Fatalf("vault_search: %q", searchResult.Text)
	}

	delResult, err := tools.Dispatch("vault_delete", map[string]any{
		"name": "db.login",
	})
	if err != nil {
		t.Fatal(err)
	}
	if delResult.IsError {
		t.Fatalf("vault_delete: %s", delResult.Text)
	}
}
