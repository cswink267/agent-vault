package settings_test

import (
	"strings"
	"testing"

	"github.com/cswink267/agent-vault/internal/settings"
)

func TestRenderCaddyfile(t *testing.T) {
	active := settings.RenderCaddyfile("vault.example.com", true)
	if !strings.Contains(active, "vault.example.com") {
		t.Fatalf("active missing hostname: %q", active)
	}
	if !strings.Contains(active, "reverse_proxy agent-vault:8080") {
		t.Fatalf("active missing reverse_proxy: %q", active)
	}

	disabled := settings.RenderCaddyfile("", false)
	if !strings.Contains(disabled, "https disabled") {
		t.Fatalf("disabled missing comment: %q", disabled)
	}
}
