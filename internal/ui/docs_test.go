package ui

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cswink267/agent-vault/internal/vault"
)

func TestRewriteDocLinks(t *testing.T) {
	in := "See [Concepts](concepts.md) and [Install](install-and-ops.md#https)."
	out := rewriteDocLinks(in)
	if !strings.Contains(out, "](/ui/docs/concepts)") {
		t.Fatalf("concepts link: %s", out)
	}
	if !strings.Contains(out, "](/ui/docs/install-and-ops#https)") {
		t.Fatalf("install fragment link: %s", out)
	}

	stripped := rewriteDocLinks("See the [skill](../skills/SKILL.md) and [history](superpowers/specs/x.md).")
	if strings.Contains(stripped, "](") {
		t.Fatalf("expected repo links stripped, got %q", stripped)
	}
	if !strings.Contains(stripped, "skill") || !strings.Contains(stripped, "history") {
		t.Fatalf("expected link text kept: %q", stripped)
	}
}

func TestRenderDocMarkdown(t *testing.T) {
	g, html, err := renderDocMarkdown("concepts")
	if err != nil {
		t.Fatal(err)
	}
	if g.Title != "Concepts" {
		t.Fatalf("title %q", g.Title)
	}
	body := string(html)
	if !strings.Contains(body, "<h1") || !strings.Contains(strings.ToLower(body), "concepts") {
		t.Fatalf("unexpected html: %s", body[:min(200, len(body))])
	}

	if _, _, err := renderDocMarkdown("nope"); err == nil {
		t.Fatal("expected unknown slug error")
	}
}

func TestDocsPagesAuthAndContent(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir, "test-passphrase-ok")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(v, nil, false).Handler())
	defer ts.Close()

	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noRedirect.Get(ts.URL + "/ui/docs")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unauth status %d", resp.StatusCode)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	resp, err = client.Post(ts.URL+"/ui/login", "application/json", strings.NewReader(`{"passphrase":"test-passphrase-ok"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	resp, err = client.Get(ts.URL + "/ui/docs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("docs index %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, "Documentation") || !strings.Contains(body, "/ui/docs/concepts") {
		t.Fatalf("missing docs chrome: %s", body[:min(400, len(body))])
	}
	if !strings.Contains(body, "Docs</a>") {
		t.Fatal("nav missing Docs link")
	}

	resp, err = client.Get(ts.URL + "/ui/docs/cli")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cli guide %d", resp.StatusCode)
	}

	resp, err = client.Get(ts.URL + "/ui/docs/superpowers")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("superpowers slug status %d, want 404", resp.StatusCode)
	}
}
