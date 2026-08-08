package ui_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cswink267/agent-vault/internal/security"
	"github.com/cswink267/agent-vault/internal/ui"
	"github.com/cswink267/agent-vault/internal/vault"
)

func TestUILoginCRUDRevealAndCSRF(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	// login
	resp, err := client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"test-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status %d body %s", resp.StatusCode, b)
	}
	var loginBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&loginBody); err != nil {
		t.Fatal(err)
	}
	if loginBody["ok"] != true {
		t.Fatalf("login ok: %v", loginBody["ok"])
	}
	if loginBody["sealed"] != false {
		t.Fatalf("login sealed: %v", loginBody["sealed"])
	}

	csrf := csrfFromJar(t, jar, ts.URL)
	if csrf == "" {
		t.Fatal("missing CSRF cookie after login")
	}

	// POST secret without CSRF → 403
	resp, err = client.Post(ts.URL+"/ui/api/secrets", "application/json", strings.NewReader(`{"name":"k","type":"api_key","secret":"abc","tags":["t"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("post without csrf status %d body %s", resp.StatusCode, b)
	}

	// POST with CSRF → 201
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/api/secrets", strings.NewReader(`{"name":"k","type":"api_key","secret":"abc","tags":["t"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("post with csrf status %d body %s", resp.StatusCode, b)
	}

	// GET list → no secret field
	resp, err = client.Get(ts.URL + "/ui/api/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status %d", resp.StatusCode)
	}
	var list []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len %d", len(list))
	}
	if _, ok := list[0]["secret"]; ok {
		t.Fatalf("list must not include secret: %v", list[0])
	}
	if _, ok := list[0]["username"]; ok {
		t.Fatalf("list must not include username: %v", list[0])
	}

	// GET ?reveal=1 → secret present
	resp, err = client.Get(ts.URL + "/ui/api/secrets/k?reveal=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reveal status %d body %s", resp.StatusCode, b)
	}
	var revealed map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&revealed); err != nil {
		t.Fatal(err)
	}
	if revealed["secret"] != "abc" {
		t.Fatalf("revealed secret: %v", revealed["secret"])
	}

	// lock → sealed; reveal → 503
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/ui/api/lock", nil)
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("lock status %d body %s", resp.StatusCode, b)
	}

	resp, err = client.Get(ts.URL + "/ui/api/secrets/k?reveal=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reveal when sealed status %d body %s", resp.StatusCode, b)
	}

	// unlock via /ui/api/unlock with passphrase + CSRF
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/ui/api/unlock", strings.NewReader(`{"passphrase":"test-passphrase"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unlock status %d body %s", resp.StatusCode, b)
	}

	resp, err = client.Get(ts.URL + "/ui/api/secrets/k?reveal=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reveal after unlock status %d body %s", resp.StatusCode, b)
	}
}

func TestUIChangePassphrase(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "old-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"old-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status %d body %s", resp.StatusCode, b)
	}
	csrf := csrfFromJar(t, jar, ts.URL)
	if csrf == "" {
		t.Fatal("missing CSRF cookie after login")
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/api/change-passphrase", strings.NewReader(`{"old_passphrase":"wrong","new_passphrase":"new-passphrase"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("wrong old status %d body %s", resp.StatusCode, b)
	}

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/ui/api/change-passphrase", strings.NewReader(`{"old_passphrase":"old-passphrase","new_passphrase":"new-passphrase"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
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
	newTok, _ := changeBody["token"].(string)
	if newTok == "" {
		t.Fatal("expected root token in UI change response")
	}

	if err := v.VerifyPassphrase("new-passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyPassphrase("old-passphrase"); err == nil {
		t.Fatal("old passphrase should fail")
	}
}

func TestUIRotateMaster(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("root", vault.Secret{Name: "k", Type: "note", Secret: "v"}); err != nil {
		t.Fatal(err)
	}
	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	resp, err := client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"test-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %d", resp.StatusCode)
	}
	csrf := csrfFromJar(t, jar, ts.URL)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/api/rotate-master", strings.NewReader(`{"passphrase":"test-passphrase"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("rotate status %d body %s", resp.StatusCode, b)
	}
	got, err := v.Get("root", "k", true)
	if err != nil || got.Secret != "v" {
		t.Fatalf("secret after ui rotate: %+v err %v", got, err)
	}
}

func TestUILoginWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"wrong"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("wrong passphrase status %d body %s", resp.StatusCode, b)
	}
}

func TestUILoginRateLimit(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	lim := security.NewAttemptLimiter(3, time.Hour)
	uiSrv := ui.New(v, lim, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"wrong-passphrase"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d", i+1, resp.StatusCode)
		}
	}
	resp, err := http.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"wrong-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 429, got %d body %s", resp.StatusCode, b)
	}
}

func TestUIAPIRequiresSession(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ui/api/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list status %d", resp.StatusCode)
	}
}

func TestUIPagesAuth(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := noRedirect.Get(ts.URL + "/ui/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unauthenticated /ui/secrets status %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/ui/login") {
		t.Fatalf("redirect location %q, want /ui/login", loc)
	}

	resp, err = http.Get(ts.URL + "/ui/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login page status %d, want 200", resp.StatusCode)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	resp, err = client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"test-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	resp, err = client.Get(ts.URL + "/ui/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated /ui/secrets status %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	page := string(body)
	if !strings.Contains(page, "Secrets") {
		t.Fatalf("list page body missing 'Secrets': %s", page)
	}
	if strings.Contains(page, "change-passphrase-form") {
		t.Fatal("list page must not include change-passphrase form")
	}
	if strings.Contains(page, "btn-backup-snapshot") {
		t.Fatal("list page must not include backup controls")
	}
}

func TestUIUpdateWithRevealedPayload(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"test-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	csrf := csrfFromJar(t, jar, ts.URL)
	if csrf == "" {
		t.Fatal("missing CSRF cookie after login")
	}

	createBody := `{"name":"edit-test","type":"api_key","secret":"original-secret","tags":["t"]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/api/secrets", strings.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status %d body %s", resp.StatusCode, b)
	}

	// GET without reveal — PUT with empty secret must be rejected
	resp, err = client.Get(ts.URL + "/ui/api/secrets/edit-test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status %d", resp.StatusCode)
	}

	emptyPut := `{"type":"api_key","secret":"","username":"","url":"","tags":["t"],"notes":""}`
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/ui/api/secrets/edit-test", strings.NewReader(emptyPut))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("put empty secret status %d body %s, want 400", resp.StatusCode, b)
	}

	// Reveal then PUT with full payload succeeds
	resp, err = client.Get(ts.URL + "/ui/api/secrets/edit-test?reveal=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reveal status %d body %s", resp.StatusCode, b)
	}
	var revealed map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&revealed); err != nil {
		t.Fatal(err)
	}
	if revealed["secret"] != "original-secret" {
		t.Fatalf("revealed secret: %v", revealed["secret"])
	}

	updateBody := `{"type":"token","secret":"original-secret","username":"u","url":"https://example.com","tags":["t","updated"],"notes":"n"}`
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/ui/api/secrets/edit-test", strings.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("put with revealed payload status %d body %s", resp.StatusCode, b)
	}

	resp, err = client.Get(ts.URL + "/ui/api/secrets/edit-test?reveal=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reveal after update status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&revealed); err != nil {
		t.Fatal(err)
	}
	if revealed["secret"] != "original-secret" {
		t.Fatalf("secret after update: %v", revealed["secret"])
	}
	if revealed["type"] != "token" {
		t.Fatalf("type after update: %v", revealed["type"])
	}
	if revealed["username"] != "u" {
		t.Fatalf("username after update: %v", revealed["username"])
	}
}

func TestUIBackupSnapshot(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/ui/api/backup/snapshot", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session snapshot status %d want 401", resp.StatusCode)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	resp, err = client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"test-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csrf := csrfFromJar(t, jar, ts.URL)
	if csrf == "" {
		t.Fatal("missing CSRF cookie after login")
	}

	resp, err = client.Get(ts.URL + "/ui/api/backup/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET snapshot status %d want 405", resp.StatusCode)
	}

	resp, err = client.Post(ts.URL+"/ui/api/backup/snapshot", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("snapshot without csrf status %d body %s", resp.StatusCode, b)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/api/backup/snapshot", nil)
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("snapshot status %d body %s", resp.StatusCode, b)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/gzip" {
		t.Fatalf("Content-Type %q want application/gzip", ct)
	}
	cd := resp.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, "agent-vault-snapshot.avs.tar.gz") {
		t.Fatalf("Content-Disposition %q", cd)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		t.Fatalf("missing gzip magic: %x", data[:min(2, len(data))])
	}
}

func TestUIBackupExport(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("root", vault.Secret{Name: "exp", Type: "api_key", Secret: "val"}); err != nil {
		t.Fatal(err)
	}
	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/ui/api/backup/export", "application/json", strings.NewReader(`{"backup_passphrase":"backup-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session export status %d want 401", resp.StatusCode)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	resp, err = client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"test-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csrf := csrfFromJar(t, jar, ts.URL)

	resp, err = client.Post(ts.URL+"/ui/api/backup/export", "application/json", strings.NewReader(`{"backup_passphrase":"backup-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("export without csrf status %d body %s", resp.StatusCode, b)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/api/backup/export", strings.NewReader(`{"backup_passphrase":"backup-passphrase"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("export status %d body %s", resp.StatusCode, b)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/octet-stream" {
		t.Fatalf("Content-Type %q want application/octet-stream", ct)
	}
	cd := resp.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, "agent-vault-export.ave") {
		t.Fatalf("Content-Disposition %q", cd)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 4 || string(data[:4]) != "AVE1" {
		t.Fatalf("missing AVE1 magic: %q", data[:min(4, len(data))])
	}

	v.Lock()
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/ui/api/backup/export", strings.NewReader(`{"backup_passphrase":"backup-passphrase"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("sealed export status %d body %s", resp.StatusCode, b)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestUISettingsAPI(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	caddyDir := t.TempDir()
	v.SetCaddyConfigDir(caddyDir)

	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	// unauthenticated GET → 401
	resp, err := http.Get(ts.URL + "/ui/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET status %d want 401", resp.StatusCode)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	resp, err = client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"test-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csrf := csrfFromJar(t, jar, ts.URL)
	if csrf == "" {
		t.Fatal("missing CSRF cookie after login")
	}

	// PUT without CSRF → 403
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/ui/api/settings", strings.NewReader(`{"public_hostname":"vault.example.com","https_enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT without csrf status %d body %s want 403", resp.StatusCode, b)
	}

	// PUT valid with CSRF → 200
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/ui/api/settings", strings.NewReader(`{"public_hostname":"vault.example.com","https_enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT valid status %d body %s", resp.StatusCode, b)
	}
	var putBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&putBody); err != nil {
		t.Fatal(err)
	}
	if putBody["public_hostname"] != "vault.example.com" {
		t.Fatalf("put public_hostname: %v", putBody["public_hostname"])
	}
	if putBody["https_enabled"] != true {
		t.Fatalf("put https_enabled: %v", putBody["https_enabled"])
	}
	if putBody["caddyfile_status"] != "active" {
		t.Fatalf("put caddyfile_status: %v", putBody["caddyfile_status"])
	}

	// GET reflects update
	resp, err = client.Get(ts.URL + "/ui/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status %d", resp.StatusCode)
	}
	var getBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&getBody); err != nil {
		t.Fatal(err)
	}
	if getBody["public_hostname"] != "vault.example.com" {
		t.Fatalf("get public_hostname: %v", getBody["public_hostname"])
	}
	if getBody["https_enabled"] != true {
		t.Fatalf("get https_enabled: %v", getBody["https_enabled"])
	}
	if getBody["public_base_url"] != "https://vault.example.com" {
		t.Fatalf("get public_base_url: %v", getBody["public_base_url"])
	}

	// invalid hostname → 400
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/ui/api/settings", strings.NewReader(`{"public_hostname":"http://bad.example.com","https_enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ui.CSRFHeader, csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("invalid hostname status %d body %s want 400", resp.StatusCode, b)
	}
}

func TestUISettingsPage(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	uiSrv := ui.New(v, nil, false)
	ts := httptest.NewServer(uiSrv.Handler())
	defer ts.Close()

	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := noRedirect.Get(ts.URL + "/ui/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unauthenticated /ui/settings status %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/ui/login") {
		t.Fatalf("redirect location %q, want /ui/login", loc)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	resp, err = client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"test-passphrase"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	resp, err = client.Get(ts.URL + "/ui/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated /ui/settings status %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	page := string(body)
	if !strings.Contains(page, "Settings") {
		t.Fatalf("settings page body missing 'Settings'")
	}
	if !strings.Contains(page, "DNS only") || !strings.Contains(page, "grey cloud") {
		t.Fatalf("settings page missing Cloudflare checklist copy")
	}
	if !strings.Contains(page, `id="change-passphrase-form"`) {
		t.Fatal("settings page must include change-passphrase form")
	}
	if !strings.Contains(page, `id="rotate-master-form"`) {
		t.Fatal("settings page must include rotate-master form")
	}
	if !strings.Contains(page, `id="btn-backup-snapshot"`) {
		t.Fatal("settings page must include backup snapshot control")
	}
	if !strings.Contains(page, `id="btn-backup-export"`) {
		t.Fatal("settings page must include backup export control")
	}
}

func csrfFromJar(t *testing.T, jar *cookiejar.Jar, baseURL string) string {
	t.Helper()
	u, err := http.NewRequest(http.MethodGet, baseURL+"/ui/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range jar.Cookies(u.URL) {
		if c.Name == ui.CSRFCookie {
			return c.Value
		}
	}
	return ""
}
