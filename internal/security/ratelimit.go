package security

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AttemptLimiter tracks failed auth attempts per key with a sliding window.
type AttemptLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
	now      func() time.Time
}

func NewAttemptLimiter(limit int, window time.Duration) *AttemptLimiter {
	if limit <= 0 {
		limit = 5
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	return &AttemptLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
		now:      time.Now,
	}
}

// Allowed reports whether another attempt is permitted for key.
func (l *AttemptLimiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)
	kept := l.attempts[key][:0]
	for _, t := range l.attempts[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.attempts[key] = kept
	return len(kept) < l.limit
}

// Fail records a failed attempt for key.
func (l *AttemptLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)
	kept := l.attempts[key][:0]
	for _, t := range l.attempts[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.attempts[key] = append(kept, now)
}

// Success clears recorded failures for key.
func (l *AttemptLimiter) Success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

// ClientKey returns a rate-limit key for the request.
// When trustProxy is true, the first X-Forwarded-For hop is preferred.
func ClientKey(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// KDFGate limits concurrent Argon2-style derivations.
type KDFGate struct {
	sem chan struct{}
}

func NewKDFGate(maxConcurrent int) *KDFGate {
	if maxConcurrent <= 0 {
		maxConcurrent = 2
	}
	return &KDFGate{sem: make(chan struct{}, maxConcurrent)}
}

func (g *KDFGate) Acquire() {
	g.sem <- struct{}{}
}

func (g *KDFGate) Release() {
	<-g.sem
}
