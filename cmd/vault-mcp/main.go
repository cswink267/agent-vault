package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/cswink267/agent-vault/internal/client"
	"github.com/cswink267/agent-vault/internal/mcptools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	baseURL := envOr("AGENT_VAULT_URL", "http://localhost:8080")
	token := os.Getenv("AGENT_VAULT_TOKEN")
	if token == "" {
		return fmt.Errorf("AGENT_VAULT_TOKEN is required")
	}

	c := client.New(baseURL, token)
	tools := mcptools.New(c)

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "agent-vault",
		Version: "1.0.0",
	}, nil)
	tools.Register(server)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Printf("server stopped: %v", err)
		return err
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
