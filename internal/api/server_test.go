package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
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

func TestUIMountedWithoutBearer(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ui/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /ui/login status %d want 200", resp.StatusCode)
	}

	resp, err = http.Get(ts.URL + "/v1/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /v1/secrets without bearer status %d want 401", resp.StatusCode)
	}
}

func TestUISessionCannotAccessV1Secrets(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"pass"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d want 200", resp.StatusCode)
	}

	resp, err = client.Get(ts.URL + "/v1/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /v1/secrets with UI session only status %d want 401 body %s", resp.StatusCode, b)
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

	postSecret(ts.URL, token, `{"name":"audited","type":"api_key","secret":"x","tags":["prod"]}`)
	resp, err = doAuth(http.MethodGet, ts.URL+"/v1/search?q=audited", token, "")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search status %d", resp.StatusCode)
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

	resp, err = doAuth(http.MethodGet, ts.URL+"/v1/audit?limit=20", token, "")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit status %d", resp.StatusCode)
	}
	var audit []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&audit); err != nil {
		t.Fatal(err)
	}
	assertAuditActions(t, audit, "unlock", "search", "lock")
}

func TestChangePassphraseAPI(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "old-pass")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	token := res.Token

	resp, err := doAuth(http.MethodPost, ts.URL+"/v1/change-passphrase", token, `{"old_passphrase":"wrong","new_passphrase":"new-pass"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("wrong old status %d body %s", resp.StatusCode, b)
	}

	resp, err = doAuth(http.MethodPost, ts.URL+"/v1/change-passphrase", token, `{"old_passphrase":"old-pass","new_passphrase":"new-pass"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("change status %d body %s", resp.StatusCode, b)
	}
	var changeBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&changeBody); err != nil {
		t.Fatal(err)
	}
	newToken, _ := changeBody["token"].(string)
	if newToken == "" || newToken == token {
		t.Fatalf("expected new root token, got %#v", changeBody["token"])
	}

	// old bearer token is dead
	resp, err = doAuth(http.MethodPost, ts.URL+"/v1/lock", token, "")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token should be unauthorized, got %d", resp.StatusCode)
	}

	v.Lock()
	resp, err = doAuth(http.MethodPost, ts.URL+"/v1/unlock", newToken, `{"passphrase":"new-pass"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unlock with new status %d body %s", resp.StatusCode, b)
	}

	v.Lock()
	resp, err = doAuth(http.MethodPost, ts.URL+"/v1/change-passphrase", newToken, `{"old_passphrase":"new-pass","new_passphrase":"newer"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("sealed change status %d body %s", resp.StatusCode, b)
	}
}

func TestRotateMasterAPI(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("root", vault.Secret{Name: "k", Type: "api_key", Secret: "abc"}); err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := doAuth(http.MethodPost, ts.URL+"/v1/rotate-master", res.Token, `{"passphrase":"wrong"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("wrong pass status %d body %s", resp.StatusCode, b)
	}

	resp, err = doAuth(http.MethodPost, ts.URL+"/v1/rotate-master", res.Token, `{"passphrase":"pass"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("rotate status %d body %s", resp.StatusCode, b)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	newTok, _ := body["token"].(string)
	if newTok == "" {
		t.Fatal("missing token")
	}

	resp, err = doAuth(http.MethodGet, ts.URL+"/v1/secrets/k?reveal=1", newTok, "")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("get after rotate %d %s", resp.StatusCode, b)
	}
}

func TestCreateSecretConflictDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	v, res, err := vault.Init(dir, "pass")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.New(v)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token := res.Token
	resp, err := doAuth(http.MethodPost, ts.URL+"/v1/secrets", token, `{"name":"same","type":"api_key","secret":"first"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("first post status %d body %s", resp.StatusCode, b)
	}

	resp, err = doAuth(http.MethodPost, ts.URL+"/v1/secrets", token, `{"name":"same","type":"api_key","secret":"second"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("second post status %d body %s", resp.StatusCode, b)
	}

	resp, err = doAuth(http.MethodGet, ts.URL+"/v1/secrets/same?reveal=1", token, "")
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
	if secret["secret"] != "first" {
		t.Fatalf("secret overwritten after conflict: %v", secret["secret"])
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

func assertAuditActions(t *testing.T, rows []map[string]interface{}, actions ...string) {
	t.Helper()
	seen := map[string]bool{}
	for _, row := range rows {
		if action, ok := row["action"].(string); ok {
			seen[action] = true
		}
	}
	for _, action := range actions {
		if !seen[action] {
			t.Fatalf("missing audit action %q in %#v", action, rows)
		}
	}
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
