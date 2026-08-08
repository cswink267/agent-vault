package backup

import (
	"bytes"
	"errors"
)

// SnapshotEncMagic identifies passphrase-sealed snapshot archives (v2).
const SnapshotEncMagic = "AVS2"

var ErrSnapshotPassphraseRequired = errors.New("snapshot passphrase required for encrypted snapshot")

// SealSnapshotArchive wraps tar.gz snapshot bytes with Argon2id + AES-GCM.
func SealSnapshotArchive(passphrase string, tarGz []byte) ([]byte, error) {
	return sealEnvelope(SnapshotEncMagic, passphrase, tarGz)
}

// OpenSnapshotArchive decrypts an AVS2 snapshot blob to tar.gz bytes.
func OpenSnapshotArchive(passphrase string, blob []byte) ([]byte, error) {
	return openEnvelope(SnapshotEncMagic, passphrase, blob)
}

// IsEncryptedSnapshot reports whether blob looks like an AVS2 envelope.
func IsEncryptedSnapshot(blob []byte) bool {
	return len(blob) >= 4 && string(blob[:4]) == SnapshotEncMagic
}

// IsLegacySnapshotGzip reports gzip magic (legacy plaintext .avs.tar.gz).
func IsLegacySnapshotGzip(blob []byte) bool {
	return len(blob) >= 2 && blob[0] == 0x1f && blob[1] == 0x8b
}

// ExtractSnapshotAuto extracts v2 (encrypted) or v1 (gzip) snapshots into destDir.
func ExtractSnapshotAuto(blob []byte, passphrase, destDir string) (Manifest, error) {
	switch {
	case IsEncryptedSnapshot(blob):
		if passphrase == "" {
			return Manifest{}, ErrSnapshotPassphraseRequired
		}
		tarGz, err := OpenSnapshotArchive(passphrase, blob)
		if err != nil {
			return Manifest{}, err
		}
		return ExtractSnapshotTarGz(bytes.NewReader(tarGz), destDir)
	case IsLegacySnapshotGzip(blob):
		return ExtractSnapshotTarGz(bytes.NewReader(blob), destDir)
	default:
		return Manifest{}, ErrInvalidFormat
	}
}
