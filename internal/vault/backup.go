package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cswink267/agent-vault/internal/backup"
	"github.com/cswink267/agent-vault/internal/security"
)

func (v *Vault) WriteSnapshot(actor string, w io.Writer) error {
	if v.Sealed() {
		return ErrSealed
	}
	unsealPath := filepath.Join(v.dataDir, "unseal.key")
	if _, err := os.Stat(unsealPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("unseal.key not found")
		}
		return err
	}

	tmpFile, err := os.CreateTemp(v.dataDir, "snapshot-*.db")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	defer os.Remove(tmpPath)

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}
	if err := v.store.VacuumInto(tmpPath); err != nil {
		return err
	}

	manifest := backup.Manifest{
		Format:    backup.SnapshotFormat,
		Version:   backup.SnapshotVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Source:    actor,
	}
	if err := backup.WriteSnapshotTarGz(w, tmpPath, unsealPath, manifest); err != nil {
		return err
	}
	return v.store.AppendAudit(actor, "backup_snapshot", "")
}

func (v *Vault) BuildExport(actor, backupPassphrase string) ([]byte, error) {
	if v.Sealed() {
		return nil, ErrSealed
	}
	if err := security.ValidatePassphrase(backupPassphrase); err != nil {
		return nil, err
	}

	secrets, err := v.List(actor)
	if err != nil {
		return nil, err
	}

	records := make([]backup.ExportRecord, 0, len(secrets))
	for _, s := range secrets {
		revealed, err := v.Get(actor, s.Name, true)
		if err != nil {
			return nil, err
		}
		records = append(records, backup.ExportRecord{
			Name:     revealed.Name,
			Type:     revealed.Type,
			Username: revealed.Username,
			Secret:   revealed.Secret,
			URL:      revealed.URL,
			Notes:    revealed.Notes,
			Tags:     revealed.Tags,
			Metadata: revealed.Metadata,
		})
	}

	blob, err := backup.SealExport(backupPassphrase, records)
	if err != nil {
		return nil, err
	}
	if err := v.store.AppendAudit(actor, "backup_export", ""); err != nil {
		return nil, err
	}
	return blob, nil
}
