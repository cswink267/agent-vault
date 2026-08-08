package security

import (
	"fmt"
)

// MinPassphraseLength is the minimum accepted length for vault and backup passphrases.
const MinPassphraseLength = 12

// ValidatePassphrase rejects empty or short passphrases.
func ValidatePassphrase(passphrase string) error {
	if passphrase == "" {
		return fmt.Errorf("passphrase is required")
	}
	if len(passphrase) < MinPassphraseLength {
		return fmt.Errorf("passphrase must be at least %d characters", MinPassphraseLength)
	}
	return nil
}
