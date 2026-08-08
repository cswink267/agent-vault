package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cswink267/agent-vault/internal/vault"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

type AuditEntry struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"timestamp"`
	TokenLabel string `json:"token_label"`
	Action     string `json:"action"`
	SecretName string `json:"secret_name"`
}

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api error %d: %s", e.Status, e.Message)
}

func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    http.DefaultClient,
	}
}

func (c *Client) Health() (ok bool, sealed bool, err error) {
	var out struct {
		OK     bool `json:"ok"`
		Sealed bool `json:"sealed"`
	}
	if err := c.doJSON(http.MethodGet, "/health", false, nil, &out); err != nil {
		return false, false, err
	}
	return out.OK, out.Sealed, nil
}

func (c *Client) Unlock(passphrase string) error {
	body := map[string]string{"passphrase": passphrase}
	var out map[string]bool
	return c.doJSON(http.MethodPost, "/v1/unlock", true, body, &out)
}

func (c *Client) Lock() error {
	var out map[string]bool
	return c.doJSON(http.MethodPost, "/v1/lock", true, nil, &out)
}

func (c *Client) ChangePassphrase(oldPassphrase, newPassphrase string) (string, error) {
	body := map[string]string{
		"old_passphrase": oldPassphrase,
		"new_passphrase": newPassphrase,
	}
	var out struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
		Label string `json:"label"`
	}
	if err := c.doJSON(http.MethodPost, "/v1/change-passphrase", true, body, &out); err != nil {
		return "", err
	}
	return out.Token, nil
}

func (c *Client) RotateMaster(passphrase string) (string, error) {
	body := map[string]string{"passphrase": passphrase}
	var out struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
		Label string `json:"label"`
	}
	if err := c.doJSON(http.MethodPost, "/v1/rotate-master", true, body, &out); err != nil {
		return "", err
	}
	return out.Token, nil
}

func (c *Client) List() ([]vault.Secret, error) {
	var raw []secretJSON
	if err := c.doJSON(http.MethodGet, "/v1/secrets", true, nil, &raw); err != nil {
		return nil, err
	}
	return secretsFromJSON(raw), nil
}

func (c *Client) Get(name string, reveal bool) (vault.Secret, error) {
	path := "/v1/secrets/" + url.PathEscape(name)
	if reveal {
		path += "?reveal=1"
	}
	var raw secretJSON
	if err := c.doJSON(http.MethodGet, path, true, nil, &raw); err != nil {
		return vault.Secret{}, err
	}
	return raw.toSecret(), nil
}

func (c *Client) Put(sec vault.Secret) (vault.Secret, error) {
	body := secretToBody(sec)
	var raw secretJSON
	err := c.doJSON(http.MethodPost, "/v1/secrets", true, body, &raw)
	if apiErr, ok := err.(*APIError); ok && apiErr.Status == http.StatusConflict {
		path := "/v1/secrets/" + url.PathEscape(sec.Name)
		err = c.doJSON(http.MethodPut, path, true, body, &raw)
	}
	if err != nil {
		return vault.Secret{}, err
	}
	return raw.toSecret(), nil
}

func (c *Client) Delete(name string) error {
	path := "/v1/secrets/" + url.PathEscape(name)
	return c.doNoContent(http.MethodDelete, path, true)
}

func (c *Client) Search(q, tag, typ string) ([]vault.Secret, error) {
	params := url.Values{}
	if q != "" {
		params.Set("q", q)
	}
	if tag != "" {
		params.Set("tag", tag)
	}
	if typ != "" {
		params.Set("type", typ)
	}
	path := "/v1/search"
	if enc := params.Encode(); enc != "" {
		path += "?" + enc
	}
	var raw []secretJSON
	if err := c.doJSON(http.MethodGet, path, true, nil, &raw); err != nil {
		return nil, err
	}
	return secretsFromJSON(raw), nil
}

func (c *Client) Audit(limit int) ([]AuditEntry, error) {
	path := "/v1/audit"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var out []AuditEntry
	if err := c.doJSON(http.MethodGet, path, true, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CreateToken(label string) (token string, outLabel string, err error) {
	body := map[string]string{"label": label}
	var resp struct {
		Token string `json:"token"`
		Label string `json:"label"`
	}
	if err := c.doJSON(http.MethodPost, "/v1/tokens", true, body, &resp); err != nil {
		return "", "", err
	}
	return resp.Token, resp.Label, nil
}

type secretJSON struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Username  string            `json:"username"`
	Secret    string            `json:"secret"`
	URL       string            `json:"url"`
	Tags      []string          `json:"tags"`
	Notes     string            `json:"notes"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt string            `json:"created_at"`
	UpdatedAt string            `json:"updated_at"`
	Version   int               `json:"version"`
}

func (s secretJSON) toSecret() vault.Secret {
	tags := s.Tags
	if tags == nil {
		tags = []string{}
	}
	meta := s.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	return vault.Secret{
		ID:        s.ID,
		Name:      s.Name,
		Type:      s.Type,
		Username:  s.Username,
		Secret:    s.Secret,
		URL:       s.URL,
		Tags:      tags,
		Notes:     s.Notes,
		Metadata:  meta,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
		Version:   s.Version,
	}
}

func secretsFromJSON(raw []secretJSON) []vault.Secret {
	out := make([]vault.Secret, len(raw))
	for i, s := range raw {
		out[i] = s.toSecret()
	}
	return out
}

func secretToBody(sec vault.Secret) map[string]interface{} {
	body := map[string]interface{}{
		"name":   sec.Name,
		"type":   sec.Type,
		"secret": sec.Secret,
	}
	if sec.Username != "" {
		body["username"] = sec.Username
	}
	if sec.URL != "" {
		body["url"] = sec.URL
	}
	if len(sec.Tags) > 0 {
		body["tags"] = sec.Tags
	}
	if sec.Notes != "" {
		body["notes"] = sec.Notes
	}
	if len(sec.Metadata) > 0 {
		body["metadata"] = sec.Metadata
	}
	return body
}

func (c *Client) doJSON(method, path string, auth bool, body interface{}, out interface{}) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth && c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &errBody)
		msg := errBody.Error
		if msg == "" {
			msg = string(data)
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) doNoContent(method, path string, auth bool) error {
	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	if auth && c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(resp.Body)
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &errBody)
		msg := errBody.Error
		if msg == "" {
			msg = string(data)
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	return nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
