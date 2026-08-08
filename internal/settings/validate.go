package settings

import (
	"errors"
	"strings"
)

var ErrInvalidHostname = errors.New("invalid hostname")

func ValidateHostname(host string) error {
	if host == "" {
		return nil
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/ \t\n\r") {
		return ErrInvalidHostname
	}
	if len(host) > 253 {
		return ErrInvalidHostname
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return ErrInvalidHostname
		}
		for i, c := range label {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return ErrInvalidHostname
			}
			if c == '-' && (i == 0 || i == len(label)-1) {
				return ErrInvalidHostname
			}
		}
	}
	return nil
}
