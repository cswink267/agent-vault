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
	ErrInvalidExportMagic = errors.New("invalid export magic")
	ErrExportTooShort     = errors.New("export blob too short")
)

func SealExport(passphrase string, records []ExportRecord) ([]byte, error) {
	plaintext, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext, err := sealAESGCM(key, plaintext)
	if err != nil {
		return nil, err
	}

	return encodeExportBlob(salt, nonce, ciphertext), nil
}

func OpenExport(passphrase string, blob []byte) ([]ExportRecord, error) {
	salt, nonce, ciphertext, err := decodeExportBlob(blob)
	if err != nil {
		return nil, err
	}

	key, err := crypto.DeriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}

	plaintext, err := openAESGCM(key, nonce, ciphertext)
	if err != nil {
		return nil, err
	}

	var records []ExportRecord
	if err := json.Unmarshal(plaintext, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func encodeExportBlob(salt, nonce, ciphertext []byte) []byte {
	out := make([]byte, 0, 4+2+len(salt)+2+len(nonce)+len(ciphertext))
	out = append(out, ExportMagic...)
	out = appendUint16BE(out, uint16(len(salt)))
	out = append(out, salt...)
	out = appendUint16BE(out, uint16(len(nonce)))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out
}

func decodeExportBlob(blob []byte) (salt, nonce, ciphertext []byte, err error) {
	if len(blob) < 4+2+2 {
		return nil, nil, nil, ErrExportTooShort
	}
	if string(blob[:4]) != ExportMagic {
		return nil, nil, nil, ErrInvalidExportMagic
	}
	off := 4

	saltLen, n := readUint16BE(blob, off)
	off += n
	if saltLen == 0 || off+int(saltLen) > len(blob) {
		return nil, nil, nil, ErrExportTooShort
	}
	salt = blob[off : off+int(saltLen)]
	off += int(saltLen)

	nonceLen, n := readUint16BE(blob, off)
	off += n
	if nonceLen == 0 || off+int(nonceLen) > len(blob) {
		return nil, nil, nil, ErrExportTooShort
	}
	nonce = blob[off : off+int(nonceLen)]
	off += int(nonceLen)

	if off >= len(blob) {
		return nil, nil, nil, ErrExportTooShort
	}
	ciphertext = blob[off:]
	return salt, nonce, ciphertext, nil
}

func appendUint16BE(b []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
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
