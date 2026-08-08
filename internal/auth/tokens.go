package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

func NewToken() (plaintext string, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	plaintext = "avt_" + hex.EncodeToString(b)
	hash = HashToken(plaintext)
	return plaintext, hash, nil
}

func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func VerifyToken(plaintext, hash string) bool {
	expected := HashToken(plaintext)
	if len(expected) != len(hash) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(hash)) == 1
}
