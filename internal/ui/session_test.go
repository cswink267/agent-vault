package ui_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/cswink267/agent-vault/internal/ui"
)

func TestSessionCreateGetExpireCSRF(t *testing.T) {
	s := ui.NewSessions(time.Hour, 2*time.Hour)
	id, csrf, err := s.Create()
	if err != nil || id == "" || csrf == "" {
		t.Fatalf("%v %q %q", err, id, csrf)
	}
	if !s.Get(id) {
		t.Fatal("missing session")
	}
	got, ok := s.CSRF(id)
	if !ok || got != csrf {
		t.Fatal("csrf mismatch")
	}
	s.Delete(id)
	if s.Get(id) {
		t.Fatal("deleted session still present")
	}
}

func TestWantSecure(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://x", nil)
	if ui.WantSecure(r) {
		t.Fatal("plain http")
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	if !ui.WantSecure(r) {
		t.Fatal("expected secure")
	}
}
