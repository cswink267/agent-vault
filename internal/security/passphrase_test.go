package security

import "testing"

func TestValidatePassphrase(t *testing.T) {
	if err := ValidatePassphrase(""); err == nil {
		t.Fatal("empty should fail")
	}
	if err := ValidatePassphrase("short"); err == nil {
		t.Fatal("short should fail")
	}
	if err := ValidatePassphrase("twelvechars!"); err != nil {
		t.Fatalf("12 chars should pass: %v", err)
	}
}
