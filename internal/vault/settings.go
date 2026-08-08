package vault

import (
	"net"
	"os"
	"path/filepath"

	"github.com/cswink267/agent-vault/internal/security"
	"github.com/cswink267/agent-vault/internal/settings"
	"github.com/cswink267/agent-vault/internal/store"
)

const defaultPrivateBaseURL = "http://localhost:8200"

type SettingsView struct {
	PublicHostname  string
	HTTPSEnabled    bool
	IPAllowlist     string
	UpdatedAt       string
	PrivateBaseURL  string
	PublicBaseURL   string
	CaddyfileStatus string
	ApplyHint       string
	CaddyConfigPath string
}

func (v *Vault) SetCaddyConfigDir(dir string) {
	v.caddyConfigDir = dir
}

func (v *Vault) GetSettings() (SettingsView, error) {
	st, err := v.store.GetSettings()
	if err != nil {
		return SettingsView{}, err
	}
	return buildSettingsView(st, v.caddyConfigDir), nil
}

func (v *Vault) UpdateSettings(publicHostname string, httpsEnabled bool, ipAllowlist string, actorLabel ...string) (SettingsView, error) {
	if err := settings.ValidateHostname(publicHostname); err != nil {
		return SettingsView{}, err
	}
	if _, err := security.ParseAllowlist(ipAllowlist); err != nil {
		return SettingsView{}, err
	}

	st := store.Settings{
		PublicHostname: publicHostname,
		HTTPSEnabled:   httpsEnabled,
		IPAllowlist:    ipAllowlist,
	}
	if err := v.store.PutSettings(st); err != nil {
		return SettingsView{}, err
	}

	content := settings.RenderCaddyfile(publicHostname, httpsEnabled)
	if v.caddyConfigDir != "" {
		if err := writeCaddyfileAtomic(v.caddyConfigDir, content); err != nil {
			return SettingsView{}, err
		}
	}

	actor := ""
	if len(actorLabel) > 0 {
		actor = actorLabel[0]
	}
	if err := v.store.AppendAudit(actor, "settings_update", ""); err != nil {
		return SettingsView{}, err
	}

	if err := v.reloadAllowlistLocked(); err != nil {
		return SettingsView{}, err
	}

	updated, err := v.store.GetSettings()
	if err != nil {
		return SettingsView{}, err
	}
	return buildSettingsView(updated, v.caddyConfigDir), nil
}

// IPAllowlist returns the currently loaded allowlist networks (nil = allow all).
func (v *Vault) IPAllowlist() []*net.IPNet {
	v.allowMu.RLock()
	defer v.allowMu.RUnlock()
	return v.allowlist
}

func (v *Vault) loadAllowlist() error {
	return v.reloadAllowlistLocked()
}

func (v *Vault) reloadAllowlistLocked() error {
	st, err := v.store.GetSettings()
	if err != nil {
		return err
	}
	list, err := security.ParseAllowlist(st.IPAllowlist)
	if err != nil {
		return err
	}
	v.allowMu.Lock()
	v.allowlist = list
	v.allowMu.Unlock()
	return nil
}

func buildSettingsView(st store.Settings, caddyConfigDir string) SettingsView {
	active := st.HTTPSEnabled && st.PublicHostname != ""
	status := "disabled"
	applyHint := "Set a public hostname, configure DNS (grey cloud A/AAAA records pointing to this host), enable HTTPS, save, then run: docker compose --profile https up -d"
	if active {
		status = "active"
		applyHint = "docker compose --profile https up -d"
	}

	publicBaseURL := ""
	if st.PublicHostname != "" {
		publicBaseURL = "https://" + st.PublicHostname
	}

	caddyPath := ""
	if caddyConfigDir != "" {
		caddyPath = filepath.Join(caddyConfigDir, "Caddyfile")
	}

	return SettingsView{
		PublicHostname:  st.PublicHostname,
		HTTPSEnabled:    st.HTTPSEnabled,
		IPAllowlist:     st.IPAllowlist,
		UpdatedAt:       st.UpdatedAt,
		PrivateBaseURL:  privateBaseURL(),
		PublicBaseURL:   publicBaseURL,
		CaddyfileStatus: status,
		ApplyHint:       applyHint,
		CaddyConfigPath: caddyPath,
	}
}

func privateBaseURL() string {
	if v := os.Getenv("AGENT_VAULT_PRIVATE_BASE_URL"); v != "" {
		return v
	}
	return defaultPrivateBaseURL
}

func writeCaddyfileAtomic(dir, content string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmpPath := filepath.Join(dir, "Caddyfile.tmp")
	finalPath := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(tmpPath, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}
