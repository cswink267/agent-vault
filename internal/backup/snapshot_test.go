package backup_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cswink267/agent-vault/internal/backup"
	"github.com/cswink267/agent-vault/internal/store"
)

func TestVacuumIntoAndSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(dir, "copy.db")
	if err := st.VacuumInto(copyPath); err != nil {
		t.Fatal(err)
	}

	unsealKeyPath := filepath.Join(dir, "unseal.key")
	if err := os.WriteFile(unsealKeyPath, []byte("fake-unseal-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := backup.Manifest{
		Format:    backup.SnapshotFormat,
		Version:   backup.SnapshotVersion,
		CreatedAt: "2026-08-08T00:00:00Z",
		Source:    "test",
	}

	var buf bytes.Buffer
	if err := backup.WriteSnapshotTarGz(&buf, copyPath, unsealKeyPath, manifest); err != nil {
		t.Fatal(err)
	}

	destDir := filepath.Join(dir, "extracted")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := backup.ExtractSnapshotTarGz(&buf, destDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"vault.db", "unseal.key", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(destDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}

	if got.Format != manifest.Format {
		t.Fatalf("format: got %q want %q", got.Format, manifest.Format)
	}
	if got.Version != manifest.Version {
		t.Fatalf("version: got %d want %d", got.Version, manifest.Version)
	}
	if got.CreatedAt != manifest.CreatedAt {
		t.Fatalf("created_at: got %q want %q", got.CreatedAt, manifest.CreatedAt)
	}
	if got.Source != manifest.Source {
		t.Fatalf("source: got %q want %q", got.Source, manifest.Source)
	}

	info, err := os.Stat(filepath.Join(destDir, "unseal.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unseal.key mode: got %o want 0600", info.Mode().Perm())
	}
}
