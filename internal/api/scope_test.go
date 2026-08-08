package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cswink267/agent-vault/internal/api"
	"github.com/cswink267/agent-vault/internal/vault"
)

func TestAgentScopeDeniedPrivilegedRoutes(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	agentTok, err := v.CreateToken("root", "hermes", "agent")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// agent can list secrets
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+agentTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("agent secrets status %d", resp.StatusCode)
	}

	// agent cannot mint tokens
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/tokens", strings.NewReader(`{"label":"x"}`))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent create token status %d body %s", resp.StatusCode, b)
	}

	// agent cannot download snapshot
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/backup/snapshot", strings.NewReader(`{"snapshot_passphrase":"snapshot-passphrase"}`))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent snapshot status %d", resp.StatusCode)
	}

	// admin root still can list tokens
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/v1/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+res.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin list tokens status %d", resp.StatusCode)
	}
}
