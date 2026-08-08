package auth

import "testing"

func TestValidateScope(t *testing.T) {
	if err := ValidateScope(ScopeAdmin); err != nil {
		t.Fatal(err)
	}
	if err := ValidateScope(ScopeAgent); err != nil {
		t.Fatal(err)
	}
	if err := ValidateScope("root"); err == nil {
		t.Fatal("expected invalid")
	}
	if NormalizeScope("") != ScopeAgent {
		t.Fatal("default agent")
	}
}
