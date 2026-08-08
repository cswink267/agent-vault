package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Store struct {
	db *sql.DB
}

type SecretRow struct {
	ID                 string
	Name               string
	Type               string
	UsernameNonce      []byte
	UsernameCT         []byte
	UsernameWrappedDEK []byte
	SecretNonce        []byte
	SecretCT           []byte
	SecretWrappedDEK   []byte
	URL                string
	TagsJSON           string
	Notes              string
	MetadataJSON       string
	CreatedAt          string
	UpdatedAt          string
	Version            int
}

type TokenRow struct {
	ID        string
	Label     string
	Hash      string
	CreatedAt string
}

type AuditRow struct {
	ID         int64
	Timestamp  string
	TokenLabel string
	Action     string
	SecretName string
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS vault_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  username_nonce BLOB,
  username_ct BLOB,
  username_wrapped_dek BLOB,
  secret_nonce BLOB NOT NULL,
  secret_ct BLOB NOT NULL,
  secret_wrapped_dek BLOB NOT NULL,
  url TEXT NOT NULL DEFAULT '',
  tags_json TEXT NOT NULL DEFAULT '[]',
  notes TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  token_label TEXT NOT NULL,
  action TEXT NOT NULL,
  secret_name TEXT NOT NULL DEFAULT ''
);
`

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) VacuumInto(path string) error {
	_, err := s.db.Exec(`VACUUM INTO ?`, path)
	return err
}

func (s *Store) GetMeta(key string) (string, bool, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM vault_meta WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO vault_meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

func (s *Store) CreateSecret(row SecretRow) error {
	_, err := s.db.Exec(`
		INSERT INTO secrets (
			id, name, type,
			username_nonce, username_ct, username_wrapped_dek,
			secret_nonce, secret_ct, secret_wrapped_dek,
			url, tags_json, notes, metadata_json,
			created_at, updated_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, row.ID, row.Name, row.Type,
		row.UsernameNonce, row.UsernameCT, row.UsernameWrappedDEK,
		row.SecretNonce, row.SecretCT, row.SecretWrappedDEK,
		row.URL, row.TagsJSON, row.Notes, row.MetadataJSON,
		row.CreatedAt, row.UpdatedAt, row.Version)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (s *Store) UpdateSecret(row SecretRow) error {
	res, err := s.db.Exec(`
		UPDATE secrets SET
			type = ?,
			username_nonce = ?, username_ct = ?, username_wrapped_dek = ?,
			secret_nonce = ?, secret_ct = ?, secret_wrapped_dek = ?,
			url = ?, tags_json = ?, notes = ?, metadata_json = ?,
			updated_at = ?, version = ?
		WHERE name = ?
	`, row.Type,
		row.UsernameNonce, row.UsernameCT, row.UsernameWrappedDEK,
		row.SecretNonce, row.SecretCT, row.SecretWrappedDEK,
		row.URL, row.TagsJSON, row.Notes, row.MetadataJSON,
		row.UpdatedAt, row.Version,
		row.Name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetSecretByName(name string) (SecretRow, error) {
	row, err := scanSecret(s.db.QueryRow(`
		SELECT id, name, type,
			username_nonce, username_ct, username_wrapped_dek,
			secret_nonce, secret_ct, secret_wrapped_dek,
			url, tags_json, notes, metadata_json,
			created_at, updated_at, version
		FROM secrets WHERE name = ?
	`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return SecretRow{}, ErrNotFound
	}
	return row, err
}

func (s *Store) DeleteSecret(name string) error {
	res, err := s.db.Exec(`DELETE FROM secrets WHERE name = ?`, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListSecrets() ([]SecretRow, error) {
	rows, err := s.db.Query(`
		SELECT id, name, type,
			username_nonce, username_ct, username_wrapped_dek,
			secret_nonce, secret_ct, secret_wrapped_dek,
			url, tags_json, notes, metadata_json,
			created_at, updated_at, version
		FROM secrets ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSecrets(rows)
}

func (s *Store) SearchSecrets(q, tag, typ string) ([]SecretRow, error) {
	var conditions []string
	var args []any

	if q != "" {
		pattern := "%" + q + "%"
		conditions = append(conditions, "(name LIKE ? OR notes LIKE ?)")
		args = append(args, pattern, pattern)
	}
	if tag != "" {
		conditions = append(conditions, `tags_json LIKE ?`)
		args = append(args, `%"`+tag+`"%`)
	}
	if typ != "" {
		conditions = append(conditions, "type = ?")
		args = append(args, typ)
	}

	query := `
		SELECT id, name, type,
			username_nonce, username_ct, username_wrapped_dek,
			secret_nonce, secret_ct, secret_wrapped_dek,
			url, tags_json, notes, metadata_json,
			created_at, updated_at, version
		FROM secrets`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY name"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSecrets(rows)
}

func (s *Store) CreateToken(label, hash string) (TokenRow, error) {
	row := TokenRow{
		ID:        uuid.NewString(),
		Label:     label,
		Hash:      hash,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	_, err := s.db.Exec(`
		INSERT INTO tokens (id, label, hash, created_at) VALUES (?, ?, ?, ?)
	`, row.ID, row.Label, row.Hash, row.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return TokenRow{}, ErrConflict
		}
		return TokenRow{}, err
	}
	return row, nil
}

func (s *Store) ListTokens() ([]TokenRow, error) {
	rows, err := s.db.Query(`SELECT id, label, hash, created_at FROM tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenRow
	for rows.Next() {
		var r TokenRow
		if err := rows.Scan(&r.ID, &r.Label, &r.Hash, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) FindTokenByHash(hash string) (TokenRow, bool, error) {
	var r TokenRow
	err := s.db.QueryRow(`SELECT id, label, hash, created_at FROM tokens WHERE hash = ?`, hash).
		Scan(&r.ID, &r.Label, &r.Hash, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenRow{}, false, nil
	}
	if err != nil {
		return TokenRow{}, false, err
	}
	return r, true, nil
}

func (s *Store) DeleteAllTokens() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM tokens`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ApplyMasterRotation atomically updates secret DEK wraps and master wrap metadata.
func (s *Store) ApplyMasterRotation(rows []SecretRow, saltHex, wrappedMasterHex, masterCheckHex string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, row := range rows {
		res, err := tx.Exec(`
			UPDATE secrets SET
				username_nonce = ?, username_ct = ?, username_wrapped_dek = ?,
				secret_nonce = ?, secret_ct = ?, secret_wrapped_dek = ?,
				updated_at = ?, version = ?
			WHERE id = ?
		`, row.UsernameNonce, row.UsernameCT, row.UsernameWrappedDEK,
			row.SecretNonce, row.SecretCT, row.SecretWrappedDEK,
			row.UpdatedAt, row.Version,
			row.ID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("secret %s not updated", row.Name)
		}
	}

	for _, kv := range [][2]string{
		{"salt", saltHex},
		{"wrapped_master", wrappedMasterHex},
		{"master_check", masterCheckHex},
	} {
		if _, err := tx.Exec(`
			INSERT INTO vault_meta (key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, kv[0], kv[1]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AppendAudit(tokenLabel, action, secretName string) error {
	_, err := s.db.Exec(`
		INSERT INTO audit (ts, token_label, action, secret_name) VALUES (?, ?, ?, ?)
	`, time.Now().UTC().Format(time.RFC3339), tokenLabel, action, secretName)
	return err
}

func (s *Store) ListAudit(limit int) ([]AuditRow, error) {
	rows, err := s.db.Query(`
		SELECT id, ts, token_label, action, secret_name
		FROM audit ORDER BY id DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.TokenLabel, &r.Action, &r.SecretName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanSecret(row scanner) (SecretRow, error) {
	var r SecretRow
	err := row.Scan(
		&r.ID, &r.Name, &r.Type,
		&r.UsernameNonce, &r.UsernameCT, &r.UsernameWrappedDEK,
		&r.SecretNonce, &r.SecretCT, &r.SecretWrappedDEK,
		&r.URL, &r.TagsJSON, &r.Notes, &r.MetadataJSON,
		&r.CreatedAt, &r.UpdatedAt, &r.Version,
	)
	return r, err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanSecrets(rows *sql.Rows) ([]SecretRow, error) {
	var out []SecretRow
	for rows.Next() {
		var r SecretRow
		err := rows.Scan(
			&r.ID, &r.Name, &r.Type,
			&r.UsernameNonce, &r.UsernameCT, &r.UsernameWrappedDEK,
			&r.SecretNonce, &r.SecretCT, &r.SecretWrappedDEK,
			&r.URL, &r.TagsJSON, &r.Notes, &r.MetadataJSON,
			&r.CreatedAt, &r.UpdatedAt, &r.Version,
		)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed")
}
