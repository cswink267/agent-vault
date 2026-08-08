package mcptools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cswink267/agent-vault/internal/client"
	"github.com/cswink267/agent-vault/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Tools struct {
	client *client.Client
}

type ToolResult struct {
	Text    string
	IsError bool
}

func New(c *client.Client) *Tools {
	return &Tools{client: c}
}

func (t *Tools) Dispatch(name string, args map[string]any) (*ToolResult, error) {
	switch name {
	case "vault_get":
		return t.vaultGet(args)
	case "vault_set":
		return t.vaultSet(args)
	case "vault_search":
		return t.vaultSearch(args)
	case "vault_list":
		return t.vaultList()
	case "vault_delete":
		return t.vaultDelete(args)
	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

func (t *Tools) Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_get",
		Description: "Get a secret by name (reveals value)",
	}, t.handleVaultGet)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_set",
		Description: "Create or update a secret",
	}, t.handleVaultSet)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_search",
		Description: "Search secrets by query, tag, or type",
	}, t.handleVaultSearch)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_list",
		Description: "List all secrets (metadata only)",
	}, t.handleVaultList)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "vault_delete",
		Description: "Delete a secret by name",
	}, t.handleVaultDelete)
}

type vaultGetArgs struct {
	Name string `json:"name" jsonschema:"secret name"`
}

type vaultSetArgs struct {
	Name     string   `json:"name" jsonschema:"secret name"`
	Type     string   `json:"type" jsonschema:"secret type"`
	Secret   string   `json:"secret" jsonschema:"secret value"`
	Username string   `json:"username,omitempty" jsonschema:"username (optional)"`
	URL      string   `json:"url,omitempty" jsonschema:"url (optional)"`
	Tags     []string `json:"tags,omitempty" jsonschema:"tags (optional)"`
	Notes    string   `json:"notes,omitempty" jsonschema:"notes (optional)"`
}

type vaultSearchArgs struct {
	Q    string `json:"q,omitempty" jsonschema:"search query (optional)"`
	Tag  string `json:"tag,omitempty" jsonschema:"filter by tag (optional)"`
	Type string `json:"type,omitempty" jsonschema:"filter by type (optional)"`
}

type vaultDeleteArgs struct {
	Name string `json:"name" jsonschema:"secret name"`
}

func (t *Tools) handleVaultGet(ctx context.Context, _ *mcp.CallToolRequest, args vaultGetArgs) (*mcp.CallToolResult, any, error) {
	result, err := t.Dispatch("vault_get", map[string]any{"name": args.Name})
	return mcpResult(result, err)
}

func (t *Tools) handleVaultSet(ctx context.Context, _ *mcp.CallToolRequest, args vaultSetArgs) (*mcp.CallToolResult, any, error) {
	m := map[string]any{
		"name":   args.Name,
		"type":   args.Type,
		"secret": args.Secret,
	}
	if args.Username != "" {
		m["username"] = args.Username
	}
	if args.URL != "" {
		m["url"] = args.URL
	}
	if len(args.Tags) > 0 {
		tags := make([]any, len(args.Tags))
		for i, tag := range args.Tags {
			tags[i] = tag
		}
		m["tags"] = tags
	}
	if args.Notes != "" {
		m["notes"] = args.Notes
	}
	result, err := t.Dispatch("vault_set", m)
	return mcpResult(result, err)
}

func (t *Tools) handleVaultSearch(ctx context.Context, _ *mcp.CallToolRequest, args vaultSearchArgs) (*mcp.CallToolResult, any, error) {
	m := map[string]any{}
	if args.Q != "" {
		m["q"] = args.Q
	}
	if args.Tag != "" {
		m["tag"] = args.Tag
	}
	if args.Type != "" {
		m["type"] = args.Type
	}
	result, err := t.Dispatch("vault_search", m)
	return mcpResult(result, err)
}

func (t *Tools) handleVaultList(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	result, err := t.Dispatch("vault_list", nil)
	return mcpResult(result, err)
}

func (t *Tools) handleVaultDelete(ctx context.Context, _ *mcp.CallToolRequest, args vaultDeleteArgs) (*mcp.CallToolResult, any, error) {
	result, err := t.Dispatch("vault_delete", map[string]any{"name": args.Name})
	return mcpResult(result, err)
}

func mcpResult(result *ToolResult, err error) (*mcp.CallToolResult, any, error) {
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: result.Text},
		},
		IsError: result.IsError,
	}, nil, nil
}

func (t *Tools) vaultGet(args map[string]any) (*ToolResult, error) {
	name, err := requiredString(args, "name")
	if err != nil {
		return toolError(err), nil
	}
	sec, err := t.client.Get(name, true)
	if err != nil {
		return toolError(err), nil
	}
	return jsonResult(secretPayload(sec, true))
}

func (t *Tools) vaultSet(args map[string]any) (*ToolResult, error) {
	name, err := requiredString(args, "name")
	if err != nil {
		return toolError(err), nil
	}
	typ, err := requiredString(args, "type")
	if err != nil {
		return toolError(err), nil
	}
	secret, err := requiredString(args, "secret")
	if err != nil {
		return toolError(err), nil
	}
	sec := vault.Secret{
		Name:     name,
		Type:     typ,
		Secret:   secret,
		Username: optionalString(args, "username"),
		URL:      optionalString(args, "url"),
		Notes:    optionalString(args, "notes"),
	}
	if tags, ok := args["tags"]; ok {
		sec.Tags = stringSlice(tags)
	}
	out, err := t.client.Put(sec)
	if err != nil {
		return toolError(err), nil
	}
	return jsonResult(secretPayload(out, false))
}

func (t *Tools) vaultSearch(args map[string]any) (*ToolResult, error) {
	q := optionalString(args, "q")
	tag := optionalString(args, "tag")
	typ := optionalString(args, "type")
	secrets, err := t.client.Search(q, tag, typ)
	if err != nil {
		return toolError(err), nil
	}
	payload := make([]map[string]any, len(secrets))
	for i, sec := range secrets {
		payload[i] = secretPayload(sec, false)
	}
	return jsonResult(payload)
}

func (t *Tools) vaultList() (*ToolResult, error) {
	secrets, err := t.client.List()
	if err != nil {
		return toolError(err), nil
	}
	payload := make([]map[string]any, len(secrets))
	for i, sec := range secrets {
		payload[i] = secretPayload(sec, false)
	}
	return jsonResult(payload)
}

func (t *Tools) vaultDelete(args map[string]any) (*ToolResult, error) {
	name, err := requiredString(args, "name")
	if err != nil {
		return toolError(err), nil
	}
	if err := t.client.Delete(name); err != nil {
		return toolError(err), nil
	}
	return jsonResult(map[string]string{"deleted": name})
}

func secretPayload(sec vault.Secret, reveal bool) map[string]any {
	out := map[string]any{
		"name":       sec.Name,
		"type":       sec.Type,
		"username":   sec.Username,
		"url":        sec.URL,
		"tags":       sec.Tags,
		"notes":      sec.Notes,
		"metadata":   sec.Metadata,
		"created_at": sec.CreatedAt,
		"updated_at": sec.UpdatedAt,
		"version":    sec.Version,
	}
	if reveal {
		out["secret"] = sec.Secret
	}
	return out
}

func requiredString(args map[string]any, key string) (string, error) {
	if args == nil {
		return "", fmt.Errorf("%s is required", key)
	}
	v, ok := args[key]
	if !ok {
		return "", fmt.Errorf("%s is required", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("%s must be a non-empty string", key)
	}
	return s, nil
}

func optionalString(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	v, ok := args[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func stringSlice(v any) []string {
	switch tags := v.(type) {
	case []string:
		return tags
	case []any:
		out := make([]string, 0, len(tags))
		for _, item := range tags {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func jsonResult(v any) (*ToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return &ToolResult{Text: string(b)}, nil
}

func toolError(err error) *ToolResult {
	return &ToolResult{Text: err.Error(), IsError: true}
}
