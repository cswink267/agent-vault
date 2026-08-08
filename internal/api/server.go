package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cswink267/agent-vault/internal/crypto"
	"github.com/cswink267/agent-vault/internal/store"
	"github.com/cswink267/agent-vault/internal/ui"
	"github.com/cswink267/agent-vault/internal/vault"
)

type contextKey string

const actorLabelKey contextKey = "actorLabel"

type Server struct {
	vault *vault.Vault
}

func New(v *vault.Vault) *Server {
	return &Server{vault: v}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /v1/unlock", s.withAuth(s.handleUnlock))
	mux.HandleFunc("POST /v1/lock", s.withAuth(s.handleLock))
	mux.HandleFunc("POST /v1/change-passphrase", s.withAuth(s.handleChangePassphrase))
	mux.HandleFunc("POST /v1/rotate-master", s.withAuth(s.handleRotateMaster))
	mux.HandleFunc("GET /v1/secrets", s.withAuth(s.handleListSecrets))
	mux.HandleFunc("POST /v1/secrets", s.withAuth(s.handleCreateSecret))
	mux.HandleFunc("GET /v1/secrets/{name}", s.withAuth(s.handleGetSecret))
	mux.HandleFunc("PUT /v1/secrets/{name}", s.withAuth(s.handleUpdateSecret))
	mux.HandleFunc("DELETE /v1/secrets/{name}", s.withAuth(s.handleDeleteSecret))
	mux.HandleFunc("GET /v1/search", s.withAuth(s.handleSearch))
	mux.HandleFunc("GET /v1/audit", s.withAuth(s.handleAudit))
	mux.HandleFunc("POST /v1/tokens", s.withAuth(s.handleCreateToken))
	uiHandler := ui.New(s.vault).Handler()
	mux.Handle("/ui/", uiHandler)
	mux.Handle("/ui", uiHandler)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":     true,
		"sealed": s.vault.Sealed(),
	})
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase   string `json:"passphrase"`
		UnsealKeyHex string `json:"unseal_key_hex"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var err error
	actor := actorFromContext(r.Context())
	if body.UnsealKeyHex != "" {
		keyBytes, decErr := hex.DecodeString(body.UnsealKeyHex)
		if decErr != nil || len(keyBytes) != crypto.MasterKeySize {
			writeError(w, http.StatusBadRequest, "invalid unseal key")
			return
		}
		var master crypto.MasterKey
		copy(master[:], keyBytes)
		err = s.vault.UnlockWithKey(master, actor)
	} else if body.Passphrase != "" {
		err = s.vault.UnlockWithPassphrase(body.Passphrase, actor)
	} else {
		writeError(w, http.StatusBadRequest, "passphrase or unseal_key_hex required")
		return
	}

	if err != nil {
		if errors.Is(err, vault.ErrInvalidMasterKey) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "unlock failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	if err := s.vault.LockWithAudit(actorFromContext(r.Context())); err != nil {
		writeVaultError(w, err)
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

	token, err := s.vault.ChangePassphrase(body.OldPassphrase, body.NewPassphrase, actorFromContext(r.Context()))
	if err != nil {
		switch {
		case errors.Is(err, vault.ErrSealed):
			writeError(w, http.StatusServiceUnavailable, "vault is sealed")
		case errors.Is(err, vault.ErrInvalidMasterKey):
			writeError(w, http.StatusUnauthorized, "invalid passphrase")
		default:
			if isValidationError(err) || strings.Contains(err.Error(), "must differ") {
				writeError(w, http.StatusBadRequest, err.Error())
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

	token, err := s.vault.RotateMasterKey(body.Passphrase, actorFromContext(r.Context()))
	if err != nil {
		switch {
		case errors.Is(err, vault.ErrSealed):
			writeError(w, http.StatusServiceUnavailable, "vault is sealed")
		case errors.Is(err, vault.ErrInvalidMasterKey):
			writeError(w, http.StatusUnauthorized, "invalid passphrase")
		default:
			if isValidationError(err) {
				writeError(w, http.StatusBadRequest, err.Error())
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

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	actor := actorFromContext(r.Context())
	secrets, err := s.vault.List(actor)
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
	out, err := s.vault.Create(actor, sec)
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

	sec, err := s.vault.Get(actor, name, reveal)
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
	if _, err := s.vault.Get(actor, name, false); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeVaultError(w, err)
		return
	}

	out, err := s.vault.Put(actor, sec)
	if err != nil {
		writeVaultError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretToJSON(out, false))
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	actor := actorFromContext(r.Context())
	if err := s.vault.Delete(actor, name); err != nil {
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

	secrets, err := s.vault.Search(actor, q, tag, typ)
	if err != nil {
		writeVaultError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretListToJSON(secrets))
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

	rows, err := s.vault.ListAudit(limit)
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

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label string `json:"label"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Label == "" {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}

	actor := actorFromContext(r.Context())
	token, err := s.vault.CreateToken(actor, body.Label)
	if err != nil {
		writeVaultError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"token": token,
		"label": body.Label,
	})
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing or invalid authorization")
			return
		}
		label, ok, err := s.vault.Authenticate(token)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "authentication error")
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing or invalid authorization")
			return
		}
		ctx := context.WithValue(r.Context(), actorLabelKey, label)
		next(w, r.WithContext(ctx))
	}
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
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
