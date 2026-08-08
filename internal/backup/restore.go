package backup

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrVaultDBExists = errors.New("vault.db already exists in data directory (use --force to overwrite)")

func RestoreSnapshotFile(in, dataDir string, force bool, passphrase string) error {
	dbPath := filepath.Join(dataDir, "vault.db")
	if _, err := os.Stat(dbPath); err == nil {
		if !force {
			return ErrVaultDBExists
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	blob, err := os.ReadFile(in)
	if err != nil {
		return err
	}

	stagingDir, err := os.MkdirTemp("", "agent-vault-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagingDir)

	if _, err := ExtractSnapshotAuto(blob, passphrase, stagingDir); err != nil {
		return err
	}
	if err := installSnapshotMembers(stagingDir, dataDir, []string{"vault.db", "unseal.key"}); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dataDir, "root.token")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
