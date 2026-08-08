package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/cswink267/agent-vault/internal/api"
	"github.com/cswink267/agent-vault/internal/vault"
)

func main() {
	port := envOr("PORT", "8080")
	dataDir := envOr("AGENT_VAULT_DATA_DIR", "/data")
	unsealKeyPath := envOr("AGENT_VAULT_UNSEAL_KEY", filepath.Join(dataDir, "unseal.key"))

	v, err := openOrInit(dataDir)
	if err != nil {
		log.Fatalf("vault setup failed: %v", err)
	}

	ok, err := v.TryAutoUnseal(unsealKeyPath)
	if err != nil {
		log.Fatalf("auto-unseal failed: %v", err)
	}
	if ok {
		log.Println("vault auto-unsealed")
	} else if v.Sealed() {
		log.Println("vault is sealed; unlock via API or CLI")
	}

	srv := api.New(v)
	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func openOrInit(dataDir string) (*vault.Vault, error) {
	dbPath := filepath.Join(dataDir, "vault.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		passphrase := os.Getenv("AGENT_VAULT_PASSPHRASE")
		if passphrase == "" {
			return nil, fmt.Errorf("vault database not found at %s: set AGENT_VAULT_PASSPHRASE and AGENT_VAULT_INIT=1 to initialize, or run vault init locally", dbPath)
		}
		if os.Getenv("AGENT_VAULT_INIT") != "1" {
			return nil, fmt.Errorf("vault database not found at %s: set AGENT_VAULT_INIT=1 with AGENT_VAULT_PASSPHRASE to initialize", dbPath)
		}
		v, res, err := vault.Init(dataDir, passphrase)
		if err != nil {
			return nil, err
		}
		log.Printf("WARNING: vault initialized; root token (save now, shown once): %s", res.Token)
		return v, nil
	}
	return vault.Open(dataDir)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
