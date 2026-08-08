package backup

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrVaultDBExists = errors.New("vault.db already exists in data directory (use --force to overwrite)")

func RestoreSnapshotFile(in, dataDir string, force bool) error {
	dbPath := filepath.Join(dataDir, "vault.db")
	if _, err := os.Stat(dbPath); err == nil {
		if !force {
			return ErrVaultDBExists
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}

	_, err = ExtractSnapshotTarGz(f, dataDir)
	return err
}
