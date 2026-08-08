package ui

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/cswink267/agent-vault/internal/store"
	"github.com/cswink267/agent-vault/internal/vault"
)

type contextKey string

const actorLabelKey contextKey = "actorLabel"

type Server struct {
	Vault    *vault.Vault
	Sessions *Sessions
}

func New(v *vault.Vault) *Server {
	return &Server{
		Vault:    v,
		Sessions: NewSessions(0, 0),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ui/login", s.handleLogin)
	mux.HandleFunc("POST /ui/logout", s.handleLogout)
	mux.HandleFunc("GET /ui/api/status", s.withSession(s.handleStatus))
	mux.HandleFunc("GET /ui/api/secrets", s.withSession(s.handleListSecrets))
	mux.HandleFunc("POST /ui/api/secrets", s.withSessionCSRF(s.handleCreateSecret))
	mux.HandleFunc("GET /ui/api/secrets/{name}", s.withSession(s.handleGetSecret))
	mux.HandleFunc("PUT /ui/api/secrets/{name}", s.withSessionCSRF(s.handleUpdateSecret))
	mux.HandleFunc("DELETE /ui/api/secrets/{name}", s.withSessionCSRF(s.handleDeleteSecret))
	mux.HandleFunc("GET /ui/api/search", s.withSession(s.handleSearch))
	mux.HandleFunc("POST /ui/api/lock", s.withSessionCSRF(s.handleLock))
	mux.HandleFunc("POST /ui/api/unlock", s.withSessionCSRF(s.handleUnlock))
	mux.HandleFunc("POST /ui/api/change-passphrase", s.withSessionCSRF(s.handleChangePassphrase))
	mux.HandleFunc("POST /ui/api/rotate-master", s.withSessionCSRF(s.handleRotateMaster))
	mux.HandleFunc("GET /ui/api/audit", s.withSession(s.handleAudit))
	mux.HandleFunc("GET /ui/api/backup/snapshot", methodNotAllowed)
	mux.HandleFunc("POST /ui/api/backup/snapshot", s.withSessionCSRF(s.handleBackupSnapshot))
	mux.HandleFunc("POST /ui/api/backup/export", s.withSessionCSRF(s.handleBackupExport))

	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /ui/static/{path...}", http.StripPrefix("/ui/static/", http.FileServer(http.FS(staticSub))))

	mux.HandleFunc("GET /ui/login", s.handleLoginPage)
	mux.HandleFunc("GET /ui", s.handleUIRoot)
	mux.HandleFunc("GET /ui/", s.withPageAuth(s.handleListPage))
	mux.HandleFunc("GET /ui/secrets", s.withPageAuth(s.handleListPage))
	mux.HandleFunc("GET /ui/secrets/new", s.withPageAuth(s.handleNewPage))
	mux.HandleFunc("GET /ui/s/{name}", s.withPageAuth(s.handleDetailPage))
	mux.HandleFunc("GET /ui/audit", s.withPageAuth(s.handleAuditPage))
	return mux
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase required")
		return
	}

	id, csrf, err := s.Sessions.Create()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	actor := actorLabel(id)

	if err := s.Vault.LoginWithPassphrase(body.Passphrase, actor); err != nil {
		s.Sessions.Delete(id)
		if errors.Is(err, vault.ErrInvalidMasterKey) {
			writeError(w, http.StatusUnauthorized, "invalid passphrase")
			return
		}
		writeError(w, http.StatusUnauthorized, "login failed")
		return
	}

	SetSessionCookies(w, r, id, csrf)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":     true,
		"sealed": s.Vault.Sealed(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if id := SessionIDFromRequest(r); id != "" {
		s.Sessions.Delete(id)
	}
	ClearSessionCookies(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sealed":        s.Vault.Sealed(),
		"authenticated": true,
	})
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	actor := actorFromContext(r.Context())
	secrets, err := s.Vault.List(actor)
	if err != nil {
		writeVaultError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretListToJSON(secrets))
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	sec, err := decodeSecret(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	actor := actorFromContext(r.Context())
	out, err := s.Vault.Create(actor, sec)
	if err != nil {
		writeVaultError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, secretToJSON(out, false))
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	reveal := r.URL.Query().Get("reveal") == "1"
	actor := actorFromContext(r.Context())

	sec, err := s.Vault.Get(actor, name, reveal)
	if err != nil {
		writeVaultError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretToJSON(sec, reveal))
}

func (s *Server) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	sec, err := decodeSecret(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sec.Name = name

	actor := actorFromContext(r.Context())
	if _, err := s.Vault.Get(actor, name, false); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeVaultError(w, err)
		return
	}

	out, err := s.Vault.Put(actor, sec)
	if err != nil {
		writeVaultError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretToJSON(out, false))
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	actor := actorFromContext(r.Context())
	if err := s.Vault.Delete(actor, name); err != nil {
		writeVaultError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	tag := r.URL.Query().Get("tag")
	typ := r.URL.Query().Get("type")
	actor := actorFromContext(r.Context())

	secrets, err := s.Vault.Search(actor, q, tag, typ)
	if err != nil {
		writeVaultError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretListToJSON(secrets))
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	actor := actorFromContext(r.Context())
	if err := s.Vault.LockWithAudit(actor); err != nil {
		writeVaultError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase required")
		return
	}

	actor := actorFromContext(r.Context())
	if err := s.Vault.UnlockWithPassphrase(body.Passphrase, actor); err != nil {
		if errors.Is(err, vault.ErrInvalidMasterKey) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "unlock failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleChangePassphrase(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassphrase string `json:"old_passphrase"`
		NewPassphrase string `json:"new_passphrase"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.OldPassphrase == "" || body.NewPassphrase == "" {
		writeError(w, http.StatusBadRequest, "old_passphrase and new_passphrase are required")
		return
	}

	actor := actorFromContext(r.Context())
	token, err := s.Vault.ChangePassphrase(body.OldPassphrase, body.NewPassphrase, actor)
	if err != nil {
		switch {
		case errors.Is(err, vault.ErrSealed):
			writeError(w, http.StatusServiceUnavailable, "vault is sealed")
		case errors.Is(err, vault.ErrInvalidMasterKey):
			writeError(w, http.StatusUnauthorized, "invalid passphrase")
		default:
			msg := err.Error()
			if strings.Contains(msg, "required") || strings.Contains(msg, "must differ") {
				writeError(w, http.StatusBadRequest, msg)
				return
			}
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":    true,
		"token": token,
		"label": "root",
	})
}

func (s *Server) handleRotateMaster(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}

	actor := actorFromContext(r.Context())
	token, err := s.Vault.RotateMasterKey(body.Passphrase, actor)
	if err != nil {
		switch {
		case errors.Is(err, vault.ErrSealed):
			writeError(w, http.StatusServiceUnavailable, "vault is sealed")
		case errors.Is(err, vault.ErrInvalidMasterKey):
			writeError(w, http.StatusUnauthorized, "invalid passphrase")
		default:
			msg := err.Error()
			if strings.Contains(msg, "required") {
				writeError(w, http.StatusBadRequest, msg)
				return
			}
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":    true,
		"token": token,
		"label": "root",
	})
}

func (s *Server) handleBackupSnapshot(w http.ResponseWriter, r *http.Request) {
	actor := actorFromContext(r.Context())
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"agent-vault-snapshot.avs.tar.gz\"")
	if err := s.Vault.WriteSnapshot(actor, w); err != nil {
		writeVaultError(w, err)
		return
	}
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BackupPassphrase string `json:"backup_passphrase"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.BackupPassphrase == "" {
		writeError(w, http.StatusBadRequest, "backup_passphrase is required")
		return
	}

	actor := actorFromContext(r.Context())
	blob, err := s.Vault.BuildExport(actor, body.BackupPassphrase)
	if err != nil {
		writeVaultError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\"agent-vault-export.ave\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = n
	}

	rows, err := s.Vault.ListAudit(limit)
	if err != nil {
		writeVaultError(w, err)
		return
	}
	out := make([]map[string]interface{}, len(rows))
	for i, row := range rows {
		out[i] = map[string]interface{}{
			"id":          row.ID,
			"timestamp":   row.Timestamp,
			"token_label": row.TokenLabel,
			"action":      row.Action,
			"secret_name": row.SecretName,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) withPageAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := SessionIDFromRequest(r)
		if id == "" || !s.Sessions.Get(id) {
			http.Redirect(w, r, "/ui/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (s *Server) renderPage(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *Server) handleUIRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/ui/", http.StatusFound)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, "login", nil)
}

func (s *Server) handleListPage(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, "list", nil)
}

func (s *Server) handleNewPage(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, "new", nil)
}

func (s *Server) handleDetailPage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.renderPage(w, "detail", map[string]string{"Name": name})
}

func (s *Server) handleAuditPage(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, "audit", nil)
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", http.MethodPost)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (s *Server) withSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := SessionIDFromRequest(r)
		if id == "" || !s.Sessions.Get(id) {
			writeError(w, http.StatusUnauthorized, "session required")
			return
		}
		ctx := context.WithValue(r.Context(), actorLabelKey, actorLabel(id))
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) withSessionCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := SessionIDFromRequest(r)
		if id == "" || !s.Sessions.Get(id) {
			writeError(w, http.StatusUnauthorized, "session required")
			return
		}
		csrf, ok := s.Sessions.CSRF(id)
		if !ok {
			writeError(w, http.StatusUnauthorized, "session required")
			return
		}
		if r.Header.Get(CSRFHeader) != csrf {
			writeError(w, http.StatusForbidden, "csrf token mismatch")
			return
		}
		ctx := context.WithValue(r.Context(), actorLabelKey, actorLabel(id))
		next(w, r.WithContext(ctx))
	}
}

func actorLabel(sessionID string) string {
	if len(sessionID) >= 8 {
		return "ui:" + sessionID[:8]
	}
	return "ui"
}

func actorFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(actorLabelKey).(string); ok {
		return v
	}
	return ""
}

func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func decodeSecret(r *http.Request) (vault.Secret, error) {
	var body struct {
		Name     string            `json:"name"`
		Type     string            `json:"type"`
		Secret   string            `json:"secret"`
		Username string            `json:"username"`
		URL      string            `json:"url"`
		Tags     []string          `json:"tags"`
		Notes    string            `json:"notes"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return vault.Secret{}, errors.New("invalid JSON")
	}
	return vault.Secret{
		Name:     body.Name,
		Type:     body.Type,
		Secret:   body.Secret,
		Username: body.Username,
		URL:      body.URL,
		Tags:     body.Tags,
		Notes:    body.Notes,
		Metadata: body.Metadata,
	}, nil
}

func secretToJSON(sec vault.Secret, includeSensitive bool) map[string]interface{} {
	out := map[string]interface{}{
		"id":         sec.ID,
		"name":       sec.Name,
		"type":       sec.Type,
		"url":        sec.URL,
		"tags":       sec.Tags,
		"notes":      sec.Notes,
		"metadata":   sec.Metadata,
		"created_at": sec.CreatedAt,
		"updated_at": sec.UpdatedAt,
		"version":    sec.Version,
	}
	if includeSensitive {
		out["secret"] = sec.Secret
		if sec.Username != "" {
			out["username"] = sec.Username
		}
	}
	return out
}

func secretListToJSON(secrets []vault.Secret) []map[string]interface{} {
	out := make([]map[string]interface{}, len(secrets))
	for i, sec := range secrets {
		out[i] = secretToJSON(sec, false)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeVaultError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, vault.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")
	default:
		if isValidationError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func isValidationError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "required") ||
		strings.Contains(msg, "invalid type") ||
		strings.Contains(msg, "invalid")
}
