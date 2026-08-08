package store_test

import (
	"path/filepath"
	"testing"

	"github.com/cswink267/agent-vault/internal/store"
)

func TestSecretCRUDAndSearch(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	row := store.SecretRow{
		ID: "id1", Name: "openai.api_key", Type: "api_key",
		SecretNonce: []byte("n"), SecretCT: []byte("c"), SecretWrappedDEK: []byte("w"),
		URL: "https://api.openai.com", TagsJSON: `["cursor"]`, Notes: "main",
		MetadataJSON: `{}`, CreatedAt: "t1", UpdatedAt: "t1", Version: 1,
	}
	if err := s.CreateSecret(row); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSecret(row); err != store.ErrConflict {
		t.Fatalf("want conflict, got %v", err)
	}
	got, err := s.GetSecretByName("openai.api_key")
	if err != nil || got.Name != row.Name {
		t.Fatalf("get: %v %+v", err, got)
	}
	hits, err := s.SearchSecrets("openai", "cursor", "api_key")
	if err != nil || len(hits) != 1 {
		t.Fatalf("search: %v %d", err, len(hits))
	}
	if err := s.SetMeta("salt", "abc"); err != nil {
		t.Fatal(err)
	}
	v, ok, err := s.GetMeta("salt")
	if err != nil || !ok || v != "abc" {
		t.Fatalf("meta %v %v %q", err, ok, v)
	}
	tr, err := s.CreateToken("cursor", "hash1")
	if err != nil || tr.Label != "cursor" {
		t.Fatal(err, tr)
	}
	if err := s.AppendAudit("cursor", "set", "openai.api_key"); err != nil {
		t.Fatal(err)
	}
	aud, err := s.ListAudit(10)
	if err != nil || len(aud) != 1 || aud[0].Action != "set" {
		t.Fatalf("audit: %v %+v", err, aud)
	}
}

func TestVacuumInto(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.SetMeta("test", "value"); err != nil {
		t.Fatal(err)
	}

	copyPath := filepath.Join(dir, "copy.db")
	if err := s.VacuumInto(copyPath); err != nil {
		t.Fatal(err)
	}

	copyStore, err := store.Open(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer copyStore.Close()

	v, ok, err := copyStore.GetMeta("test")
	if err != nil || !ok || v != "value" {
		t.Fatalf("copied meta: %v %v %q", err, ok, v)
	}
}
