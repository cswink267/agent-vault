package auth_test

import (
	"strings"
	"testing"

	"github.com/cswink267/agent-vault/internal/auth"
)

func TestNewTokenHashVerify(t *testing.T) {
	pt, hash, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pt, "avt_") {
		t.Fatalf("prefix: %s", pt)
	}
	if !auth.VerifyToken(pt, hash) {
		t.Fatal("verify failed")
	}
	if auth.VerifyToken("avt_nope", hash) {
		t.Fatal("expected fail")
	}
	if auth.HashToken(pt) != hash {
		t.Fatal("hash mismatch")
	}
}
