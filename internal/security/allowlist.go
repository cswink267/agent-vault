package security

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ParseAllowlist parses comma/newline/space-separated IPs and CIDRs.
// Empty input means allow-all (returns nil list).
func ParseAllowlist(raw string) ([]*net.IPNet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	})
	var out []*net.IPNet
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Contains(f, "/") {
			_, n, err := net.ParseCIDR(f)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", f, err)
			}
			out = append(out, n)
			continue
		}
		ip := net.ParseIP(f)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", f)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

// IPAllowed reports whether ip is covered by allowlist. Empty allowlist allows all.
func IPAllowed(allowlist []*net.IPNet, ip net.IP) bool {
	if len(allowlist) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, n := range allowlist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowlistMiddleware returns 403 when the client IP is outside a non-empty allowlist.
// /health is always permitted. allowlistFn is called per request so settings can change live.
func AllowlistMiddleware(trustProxy bool, allowlistFn func() []*net.IPNet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		list := allowlistFn()
		if len(list) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		key := ClientKey(r, trustProxy)
		ip := net.ParseIP(key)
		if !IPAllowed(list, ip) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
