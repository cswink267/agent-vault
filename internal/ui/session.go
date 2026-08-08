package ui

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	SessionCookie = "agent_vault_session"
	CSRFCookie    = "agent_vault_csrf"
	CSRFHeader    = "X-CSRF-Token"
)

const (
	DefaultIdleTTL     = 12 * time.Hour
	DefaultAbsoluteTTL = 24 * time.Hour
)

type sessionEntry struct {
	createdAt time.Time
	lastSeen  time.Time
	csrf      string
}

type Sessions struct {
	mu       sync.Mutex
	sessions map[string]*sessionEntry
	idle     time.Duration
	absolute time.Duration
}

func NewSessions(idle, absolute time.Duration) *Sessions {
	if idle == 0 {
		idle = DefaultIdleTTL
	}
	if absolute == 0 {
		absolute = DefaultAbsoluteTTL
	}
	return &Sessions{
		sessions: make(map[string]*sessionEntry),
		idle:     idle,
		absolute: absolute,
	}
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Sessions) Create() (id, csrf string, err error) {
	id, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = &sessionEntry{
		createdAt: now,
		lastSeen:  now,
		csrf:      csrf,
	}
	return id, csrf, nil
}

func (s *Sessions) expired(e *sessionEntry, now time.Time) bool {
	if now.Sub(e.createdAt) > s.absolute {
		return true
	}
	if now.Sub(e.lastSeen) > s.idle {
		return true
	}
	return false
}

func (s *Sessions) Get(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.sessions[id]
	if !ok {
		return false
	}
	now := time.Now()
	if s.expired(e, now) {
		delete(s.sessions, id)
		return false
	}
	e.lastSeen = now
	return true
}

func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *Sessions) CSRF(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.sessions[id]
	if !ok {
		return "", false
	}
	now := time.Now()
	if s.expired(e, now) {
		delete(s.sessions, id)
		return "", false
	}
	return e.csrf, true
}

func WantSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func SetSessionCookies(w http.ResponseWriter, r *http.Request, id, csrf string) {
	secure := WantSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    id,
		Path:     "/ui",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookie,
		Value:    csrf,
		Path:     "/ui",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
}

func ClearSessionCookies(w http.ResponseWriter, r *http.Request) {
	secure := WantSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/ui",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookie,
		Value:    "",
		Path:     "/ui",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   -1,
	})
}

func SessionIDFromRequest(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}
