package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAttemptLimiter(t *testing.T) {
	l := NewAttemptLimiter(2, time.Minute)
	base := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return base }

	if !l.Allowed("a") {
		t.Fatal("first allowed")
	}
	l.Fail("a")
	l.Fail("a")
	if l.Allowed("a") {
		t.Fatal("third should be blocked")
	}
	l.Success("a")
	if !l.Allowed("a") {
		t.Fatal("after success should allow")
	}
}

func TestClientKey(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	if got := ClientKey(r, false); got != "10.0.0.5" {
		t.Fatalf("got %q", got)
	}
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := ClientKey(r, false); got != "10.0.0.5" {
		t.Fatalf("untrusted proxy should ignore xff, got %q", got)
	}
	if got := ClientKey(r, true); got != "203.0.113.9" {
		t.Fatalf("trusted proxy got %q", got)
	}
}
