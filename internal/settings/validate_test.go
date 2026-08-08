package settings_test

import (
	"testing"

	"github.com/cswink267/agent-vault/internal/settings"
)

func TestValidateHostname(t *testing.T) {
	if err := settings.ValidateHostname(""); err != nil {
		t.Fatal(err)
	}
	if err := settings.ValidateHostname("vault.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := settings.ValidateHostname("http://vault.example.com"); err == nil {
		t.Fatal("expected error")
	}
}
