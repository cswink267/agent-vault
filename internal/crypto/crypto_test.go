package crypto_test

import (
	"bytes"
	"testing"

	"github.com/cswink267/agent-vault/internal/crypto"
)

func TestSealOpenRoundTrip(t *testing.T) {
	master, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.Seal(master, []byte("s3cr3t"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := crypto.Open(master, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte("s3cr3t")) {
		t.Fatalf("got %q", out)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	m1, _ := crypto.GenerateMasterKey()
	m2, _ := crypto.GenerateMasterKey()
	blob, _ := crypto.Seal(m1, []byte("x"))
	if _, err := crypto.Open(m2, blob); err == nil {
		t.Fatal("expected error")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt, err := crypto.NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	k1, err := crypto.DeriveKey("pass", salt)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := crypto.DeriveKey("pass", salt)
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatal("expected same key")
	}
}

func TestWrapUnwrapMaster(t *testing.T) {
	master, _ := crypto.GenerateMasterKey()
	kek, _ := crypto.GenerateMasterKey()
	wrapped, err := crypto.WrapKey(master, kek)
	if err != nil {
		t.Fatal(err)
	}
	out, err := crypto.UnwrapKey(wrapped, kek)
	if err != nil {
		t.Fatal(err)
	}
	if out != master {
		t.Fatal("mismatch")
	}
}
