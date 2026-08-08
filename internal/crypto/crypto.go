package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const MasterKeySize = 32

type MasterKey [MasterKeySize]byte

type KDFParams struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

var DefaultKDFParams = KDFParams{
	Time:      3,
	MemoryKiB: 64 * 1024,
	Threads:   4,
}

type EncryptedBlob struct {
	Nonce      []byte
	Ciphertext []byte
	WrappedDEK []byte
}

func GenerateMasterKey() (MasterKey, error) {
	var k MasterKey
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return k, err
	}
	return k, nil
}

func NewSalt() ([]byte, error) {
	s := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, s); err != nil {
		return nil, err
	}
	return s, nil
}

func DeriveKey(passphrase string, salt []byte) (MasterKey, error) {
	return DeriveKeyWithParams(passphrase, salt, DefaultKDFParams)
}

func DeriveKeyWithParams(passphrase string, salt []byte, params KDFParams) (MasterKey, error) {
	var k MasterKey
	if len(salt) < 16 {
		return k, errors.New("salt must be at least 16 bytes")
	}
	if params.Time == 0 || params.MemoryKiB == 0 || params.Threads == 0 {
		return k, errors.New("invalid KDF parameters")
	}
	out := argon2.IDKey([]byte(passphrase), salt, params.Time, params.MemoryKiB, params.Threads, MasterKeySize)
	copy(k[:], out)
	return k, nil
}

func aesGCMSeal(key MasterKey, plaintext []byte) (nonce, ciphertext []byte, err error) {
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

func aesGCMOpen(key MasterKey, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func WrapKey(master, kek MasterKey) ([]byte, error) {
	nonce, ct, err := aesGCMSeal(kek, master[:])
	if err != nil {
		return nil, err
	}
	out := append(nonce, ct...)
	return out, nil
}

func UnwrapKey(wrapped []byte, kek MasterKey) (MasterKey, error) {
	var master MasterKey
	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return master, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return master, err
	}
	ns := gcm.NonceSize()
	if len(wrapped) < ns {
		return master, errors.New("wrapped key too short")
	}
	pt, err := gcm.Open(nil, wrapped[:ns], wrapped[ns:], nil)
	if err != nil {
		return master, err
	}
	if len(pt) != MasterKeySize {
		return master, fmt.Errorf("bad master key length %d", len(pt))
	}
	copy(master[:], pt)
	return master, nil
}

func Seal(master MasterKey, plaintext []byte) (EncryptedBlob, error) {
	var blob EncryptedBlob
	dek, err := GenerateMasterKey()
	if err != nil {
		return blob, err
	}
	nonce, ct, err := aesGCMSeal(dek, plaintext)
	if err != nil {
		return blob, err
	}
	wrapped, err := WrapKey(dek, master)
	if err != nil {
		return blob, err
	}
	blob.Nonce = nonce
	blob.Ciphertext = ct
	blob.WrappedDEK = wrapped
	return blob, nil
}

func Open(master MasterKey, blob EncryptedBlob) ([]byte, error) {
	dek, err := UnwrapKey(blob.WrappedDEK, master)
	if err != nil {
		return nil, err
	}
	return aesGCMOpen(dek, blob.Nonce, blob.Ciphertext)
}
