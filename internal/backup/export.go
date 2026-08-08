package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/cswink267/agent-vault/internal/crypto"
)

const ExportMagic = "AVE1"
const exportHeaderVersion byte = 1

type ExportRecord struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Username string            `json:"username,omitempty"`
	Secret   string            `json:"secret"`
	URL      string            `json:"url,omitempty"`
	Notes    string            `json:"notes,omitempty"`
	Tags     []string          `json:"tags,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

var (
	ErrInvalidExportMagic   = errors.New("invalid export magic")
	ErrInvalidExportVersion = errors.New("invalid export version")
	ErrExportTooShort       = errors.New("export blob too short")
)

func SealExport(passphrase string, records []ExportRecord) ([]byte, error) {
	plaintext, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	return sealEnvelope(ExportMagic, passphrase, plaintext)
}

func OpenExport(passphrase string, blob []byte) ([]ExportRecord, error) {
	plaintext, err := openEnvelope(ExportMagic, passphrase, blob)
	if err != nil {
		if errors.Is(err, ErrInvalidEnvelopeMagic) {
			return nil, ErrInvalidExportMagic
		}
		return nil, err
	}

	var records []ExportRecord
	if err := json.Unmarshal(plaintext, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func appendUint16BE(b []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return append(b, buf[:]...)
}

func appendUint32BE(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func readUint16BE(b []byte, off int) (uint16, int) {
	if off+2 > len(b) {
		return 0, 2
	}
	return binary.BigEndian.Uint16(b[off:]), 2
}

func sealAESGCM(key crypto.MasterKey, plaintext []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func openAESGCM(key crypto.MasterKey, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt export: %w", err)
	}
	return plaintext, nil
}
