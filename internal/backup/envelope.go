package backup

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cswink267/agent-vault/internal/crypto"
)

var ErrInvalidEnvelopeMagic = errors.New("invalid envelope magic")

func sealEnvelope(magic, passphrase string, plaintext []byte) ([]byte, error) {
	if len(magic) != 4 {
		return nil, errors.New("envelope magic must be 4 bytes")
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	kdfParams := crypto.DefaultKDFParams
	key, err := crypto.DeriveKeyWithParams(passphrase, salt, kdfParams)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext, err := sealAESGCM(key, plaintext)
	if err != nil {
		return nil, err
	}
	return encodeEnvelope(magic, kdfParams, salt, nonce, ciphertext), nil
}

func openEnvelope(magic, passphrase string, blob []byte) ([]byte, error) {
	kdfParams, salt, nonce, ciphertext, err := decodeEnvelope(magic, blob)
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveKeyWithParams(passphrase, salt, kdfParams)
	if err != nil {
		return nil, err
	}
	plaintext, err := openAESGCM(key, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt envelope: %w", err)
	}
	return plaintext, nil
}

func encodeEnvelope(magic string, kdfParams crypto.KDFParams, salt, nonce, ciphertext []byte) []byte {
	out := make([]byte, 0, 4+1+4+4+1+2+len(salt)+2+len(nonce)+len(ciphertext))
	out = append(out, magic...)
	out = append(out, exportHeaderVersion)
	out = appendUint32BE(out, kdfParams.Time)
	out = appendUint32BE(out, kdfParams.MemoryKiB)
	out = append(out, kdfParams.Threads)
	out = appendUint16BE(out, uint16(len(salt)))
	out = append(out, salt...)
	out = appendUint16BE(out, uint16(len(nonce)))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out
}

func decodeEnvelope(magic string, blob []byte) (kdfParams crypto.KDFParams, salt, nonce, ciphertext []byte, err error) {
	if len(blob) < 4+1+4+4+1+2+2 {
		return crypto.KDFParams{}, nil, nil, nil, ErrExportTooShort
	}
	if string(blob[:4]) != magic {
		return crypto.KDFParams{}, nil, nil, nil, ErrInvalidEnvelopeMagic
	}
	off := 4
	if blob[off] != exportHeaderVersion {
		return crypto.KDFParams{}, nil, nil, nil, ErrInvalidExportVersion
	}
	off++

	kdfParams.Time = binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	kdfParams.MemoryKiB = binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	kdfParams.Threads = blob[off]
	off++

	saltLen, n := readUint16BE(blob, off)
	off += n
	if saltLen == 0 || off+int(saltLen) > len(blob) {
		return crypto.KDFParams{}, nil, nil, nil, ErrExportTooShort
	}
	salt = blob[off : off+int(saltLen)]
	off += int(saltLen)

	nonceLen, n := readUint16BE(blob, off)
	off += n
	if nonceLen == 0 || off+int(nonceLen) > len(blob) {
		return crypto.KDFParams{}, nil, nil, nil, ErrExportTooShort
	}
	nonce = blob[off : off+int(nonceLen)]
	off += int(nonceLen)

	if off >= len(blob) {
		return crypto.KDFParams{}, nil, nil, nil, ErrExportTooShort
	}
	ciphertext = blob[off:]
	return kdfParams, salt, nonce, ciphertext, nil
}
