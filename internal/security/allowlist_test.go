package security

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAllowlistAndIPAllowed(t *testing.T) {
	list, err := ParseAllowlist("127.0.0.1, 10.0.0.0/8\n192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("len=%d", len(list))
	}
	if !IPAllowed(list, net.ParseIP("10.1.2.3")) {
		t.Fatal("10.x should allow")
	}
	if IPAllowed(list, net.ParseIP("8.8.8.8")) {
		t.Fatal("public should deny")
	}
	empty, err := ParseAllowlist("")
	if err != nil || empty != nil {
		t.Fatal(err, empty)
	}
	if !IPAllowed(nil, net.ParseIP("8.8.8.8")) {
		t.Fatal("empty allowlist allows all")
	}
}

func TestAllowlistMiddleware(t *testing.T) {
	list, _ := ParseAllowlist("127.0.0.1")
	h := AllowlistMiddleware(false, func() []*net.IPNet { return list }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/secrets", nil)
	req.RemoteAddr = "8.8.8.8:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/health", nil)
	req2.RemoteAddr = "8.8.8.8:1"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("health status %d", rr2.Code)
	}
}
