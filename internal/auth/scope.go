package auth

import "fmt"

const (
	ScopeAdmin = "admin"
	ScopeAgent = "agent"
)

// ValidateScope accepts admin or agent.
func ValidateScope(scope string) error {
	switch scope {
	case ScopeAdmin, ScopeAgent:
		return nil
	default:
		return fmt.Errorf("invalid scope %q (want admin or agent)", scope)
	}
}

// NormalizeScope defaults empty scope to agent for new tokens.
func NormalizeScope(scope string) string {
	if scope == "" {
		return ScopeAgent
	}
	return scope
}
