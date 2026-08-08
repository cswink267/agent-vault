package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cswink267/agent-vault/internal/api"
	"github.com/cswink267/agent-vault/internal/vault"
)

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
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status %d", resp.StatusCode)
	}
	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health["ok"] != true {
		t.Fatalf("health ok: %v", health["ok"])
	}
	if health["sealed"] != false {
		t.Fatalf("health sealed: %v", health["sealed"])
	}

	body := `{"name":"k","type":"api_key","secret":"abc","tags":["t"]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/secrets", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+res.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("post status %d body %s", resp.StatusCode, b)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/v1/secrets/k?reveal=1", nil)
	req.Header.Set("Authorization", "Bearer "+res.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get reveal status %d", resp.StatusCode)
	}
	var secret map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		t.Fatal(err)
	}
	if secret["secret"] != "abc" {
		t.Fatalf("secret value: %v", secret["secret"])
	}

	v.Lock()
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+res.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("sealed list status %d", resp.StatusCode)
	}
}

func TestUnauthorized(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d want 401", resp.StatusCode)
	}
}

func TestSearchAndTokens(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token := res.Token
	postSecret(ts.URL, token, `{"name":"findme","type":"api_key","secret":"x","tags":["prod"]}`)

	resp, err := doAuth(http.MethodGet, ts.URL+"/v1/search?q=find&tag=prod", token, "")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search status %d", resp.StatusCode)
	}
	var results []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("search results %d", len(results))
	}

	resp, err = doAuth(http.MethodPost, ts.URL+"/v1/tokens", token, `{"label":"claude"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create token status %d body %s", resp.StatusCode, b)
	}
	var tokResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tokResp["token"], "avt_") {
		t.Fatalf("token prefix: %s", tokResp["token"])
	}
	if tokResp["label"] != "claude" {
		t.Fatalf("label: %s", tokResp["label"])
	}
}

func TestUnlockLock(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token := res.Token
	resp, err := doAuth(http.MethodPost, ts.URL+"/v1/unlock", token, `{"passphrase":"pass"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unlock status %d body %s", resp.StatusCode, b)
	}

	resp, err = doAuth(http.MethodPost, ts.URL+"/v1/lock", token, "")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lock status %d", resp.StatusCode)
	}

	resp, err = http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health["sealed"] != true {
		t.Fatalf("want sealed after lock")
	}
}

func doAuth(method, url, token string, body string) (*http.Response, error) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

func postSecret(baseURL, token, body string) {
	resp, err := doAuth(http.MethodPost, baseURL+"/v1/secrets", token, body)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		panic(string(b))
	}
}
