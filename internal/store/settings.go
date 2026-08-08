package store

import (
	"database/sql"
	"errors"
	"time"
)

type Settings struct {
	PublicHostname string
	HTTPSEnabled   bool
	UpdatedAt      string
}

const (
	settingsKeyPublicHostname = "public_hostname"
	settingsKeyHTTPSEnabled     = "https_enabled"
	settingsKeyUpdatedAt        = "updated_at"
)

func (s *Store) GetSettings() (Settings, error) {
	var out Settings

	hostname, err := s.getSetting(settingsKeyPublicHostname)
	if err != nil {
		return Settings{}, err
	}
	out.PublicHostname = hostname

	enabled, err := s.getSetting(settingsKeyHTTPSEnabled)
	if err != nil {
		return Settings{}, err
	}
	out.HTTPSEnabled = enabled == "true"

	updatedAt, err := s.getSetting(settingsKeyUpdatedAt)
	if err != nil {
		return Settings{}, err
	}
	out.UpdatedAt = updatedAt

	return out, nil
}

func (s *Store) PutSettings(in Settings) error {
	updatedAt := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	entries := [][2]string{
		{settingsKeyPublicHostname, in.PublicHostname},
		{settingsKeyHTTPSEnabled, boolString(in.HTTPSEnabled)},
		{settingsKeyUpdatedAt, updatedAt},
	}
	for _, kv := range entries {
		if err := upsertSetting(tx, kv[0], kv[1]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) getSetting(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func upsertSetting(tx *sql.Tx, key, value string) error {
	_, err := tx.Exec(`
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
