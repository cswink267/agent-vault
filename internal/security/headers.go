package security

import "net/http"

// SecurityHeaders wraps h with baseline HTTP security headers.
func SecurityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "no-referrer")
		// script-src/style-src stay 'self' only — UI bootstraps from /ui/static/app.js (no inline scripts).
		hdr.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
		hdr.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.ServeHTTP(w, r)
	})
}

// SetNoStore marks the response as non-cacheable (for secret-bearing payloads).
func SetNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
