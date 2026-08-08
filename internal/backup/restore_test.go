package backup_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cswink267/agent-vault/internal/backup"
	"github.com/cswink267/agent-vault/internal/store"
)

func TestRestoreRefusesExistingDB(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "vault.db"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}

	snapPath := filepath.Join(dir, "snap.avs.tar.gz")
	if err := writeTestSnapshot(snapPath); err != nil {
		t.Fatal(err)
	}

	err := backup.RestoreSnapshotFile(snapPath, dataDir, false)
	if err == nil {
		t.Fatal("expected error when vault.db exists without force")
	}
	if err != backup.ErrVaultDBExists {
		t.Fatalf("got %v, want %v", err, backup.ErrVaultDBExists)
	}

	if err := backup.RestoreSnapshotFile(snapPath, dataDir, true); err != nil {
		t.Fatalf("restore with force: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "unseal.key")); err != nil {
		t.Fatalf("missing unseal.key after restore: %v", err)
	}
}

func writeTestSnapshot(path string) error {
	dir := filepath.Dir(path)
	st, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		return err
	}
	copyPath := filepath.Join(dir, "copy.db")
	if err := st.VacuumInto(copyPath); err != nil {
		return err
	}
	unsealKeyPath := filepath.Join(dir, "unseal.key")
	if err := os.WriteFile(unsealKeyPath, []byte("fake-unseal-key"), 0o600); err != nil {
		return err
	}
	manifest := backup.Manifest{
		Format:    backup.SnapshotFormat,
		Version:   backup.SnapshotVersion,
		CreatedAt: "2026-08-08T00:00:00Z",
		Source:    "test",
	}
	var buf bytes.Buffer
	if err := backup.WriteSnapshotTarGz(&buf, copyPath, unsealKeyPath, manifest); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}
