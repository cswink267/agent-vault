package settings

import "strings"

func RenderCaddyfile(hostname string, enabled bool) string {
	if enabled && strings.TrimSpace(hostname) != "" {
		return hostname + " {\n\treverse_proxy agent-vault:8080\n}\n"
	}
	return "# agent-vault https disabled\n:80 {\n\trespond \"agent-vault https disabled\" 404\n}\n"
}
