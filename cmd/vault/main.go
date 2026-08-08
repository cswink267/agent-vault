package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cswink267/agent-vault/internal/backup"
	"github.com/cswink267/agent-vault/internal/client"
	"github.com/cswink267/agent-vault/internal/vault"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd string, args []string) error {
	switch cmd {
	case "init":
		return cmdInit(args)
	case "unlock":
		return cmdUnlock(args)
	case "lock":
		return cmdLock(args)
	case "change-passphrase":
		return cmdChangePassphrase(args)
	case "rotate-master":
		return cmdRotateMaster(args)
	case "set":
		return cmdSet(args)
	case "get":
		return cmdGet(args)
	case "list":
		return cmdList(args)
	case "search":
		return cmdSearch(args)
	case "delete":
		return cmdDelete(args)
	case "audit":
		return cmdAudit(args)
	case "token":
		return cmdToken(args)
	case "backup":
		return cmdBackup(args)
	case "restore":
		return cmdRestore(args)
	case "export":
		return cmdExport(args)
	case "import":
		return cmdImport(args)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: vault <command> [flags]

Commands:
  init                Initialize local vault (--data-dir, --passphrase)
  unlock              Unlock remote vault (--passphrase)
  lock                Lock remote vault
  change-passphrase   Rewrap master under a new passphrase (--old, --new)
  rotate-master       Generate new master key and rewrap secrets (--passphrase)
  set                 Create or update a secret
  get                 Get a secret (reveals value)
  list                List secrets
  search              Search secrets
  delete              Delete a secret
  audit               Show audit log
  token               Token management (create)
  backup              Download snapshot archive (--out)
  restore             Restore snapshot to data directory (--in, --data-dir, --force)
  export              Download encrypted export (--passphrase, --out)
  import              Import secrets from export (--passphrase, --in, --overwrite)

Environment:
  AGENT_VAULT_URL    Base URL for remote commands (default http://localhost:8200)
  AGENT_VAULT_TOKEN  Bearer token for remote commands
`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "./data", "vault data directory")
	passphrase := fs.String("passphrase", "", "passphrase (prompted if empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pass := *passphrase
	if pass == "" {
		fmt.Fprint(os.Stderr, "Passphrase: ")
		var err error
		pass, err = readPassphrase()
		if err != nil {
			return err
		}
	}
	_, res, err := vault.Init(*dataDir, pass)
	if err != nil {
		return err
	}
	fmt.Printf("Vault initialized in %s\n", *dataDir)
	fmt.Printf("Root token written to %s\n", filepath.Join(*dataDir, "root.token"))
	fmt.Printf("Unseal key written to %s\n", filepath.Join(*dataDir, "unseal.key"))
	fmt.Printf("Root token (save now, shown once): %s\n", res.Token)
	return nil
}

func cmdUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	passphrase := fs.String("passphrase", "", "passphrase")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pass := *passphrase
	if pass == "" {
		fmt.Fprint(os.Stderr, "Passphrase: ")
		var err error
		pass, err = readPassphrase()
		if err != nil {
			return err
		}
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.Unlock(pass); err != nil {
		return err
	}
	fmt.Println("vault unlocked")
	return nil
}

func cmdLock(args []string) error {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.Lock(); err != nil {
		return err
	}
	fmt.Println("vault locked")
	return nil
}

func cmdChangePassphrase(args []string) error {
	fs := flag.NewFlagSet("change-passphrase", flag.ContinueOnError)
	oldPass := fs.String("old", "", "current passphrase")
	newPass := fs.String("new", "", "new passphrase")
	if err := fs.Parse(args); err != nil {
		return err
	}
	old := *oldPass
	if old == "" {
		fmt.Fprint(os.Stderr, "Current passphrase: ")
		var err error
		old, err = readPassphrase()
		if err != nil {
			return err
		}
	}
	neu := *newPass
	if neu == "" {
		fmt.Fprint(os.Stderr, "New passphrase: ")
		var err error
		neu, err = readPassphrase()
		if err != nil {
			return err
		}
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	token, err := c.ChangePassphrase(old, neu)
	if err != nil {
		return err
	}
	fmt.Println("passphrase changed; all bearer tokens revoked")
	fmt.Printf("New root token (save now, shown once): %s\n", token)
	fmt.Println("Update AGENT_VAULT_TOKEN / ~/.config/agent-vault env with the new token.")
	return nil
}

func cmdRotateMaster(args []string) error {
	fs := flag.NewFlagSet("rotate-master", flag.ContinueOnError)
	passphrase := fs.String("passphrase", "", "current vault passphrase")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pass := *passphrase
	if pass == "" {
		fmt.Fprint(os.Stderr, "Passphrase: ")
		var err error
		pass, err = readPassphrase()
		if err != nil {
			return err
		}
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	token, err := c.RotateMaster(pass)
	if err != nil {
		return err
	}
	fmt.Println("master key rotated; unseal.key rewritten; all bearer tokens revoked")
	fmt.Printf("New root token (save now, shown once): %s\n", token)
	fmt.Println("Update AGENT_VAULT_TOKEN / ~/.config/agent-vault env with the new token.")
	return nil
}

func cmdSet(args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	name := fs.String("name", "", "secret name")
	typ := fs.String("type", "", "secret type")
	secret := fs.String("secret", "", "secret value")
	username := fs.String("username", "", "username (optional)")
	urlVal := fs.String("url", "", "url (optional)")
	tags := fs.String("tags", "", "comma-separated tags")
	notes := fs.String("notes", "", "notes (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *typ == "" || *secret == "" {
		return fmt.Errorf("--name, --type, and --secret are required")
	}
	sec := vault.Secret{
		Name:     *name,
		Type:     *typ,
		Secret:   *secret,
		Username: *username,
		URL:      *urlVal,
		Notes:    *notes,
	}
	if *tags != "" {
		sec.Tags = splitCSV(*tags)
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	out, err := c.Put(sec)
	if err != nil {
		return err
	}
	printSecret(out, false)
	return nil
}

func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: vault get <name>")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	sec, err := c.Get(fs.Arg(0), true)
	if err != nil {
		return err
	}
	printSecret(sec, true)
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	secrets, err := c.List()
	if err != nil {
		return err
	}
	for _, sec := range secrets {
		printSecret(sec, false)
	}
	return nil
}

func cmdSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	tag := fs.String("tag", "", "filter by tag")
	typ := fs.String("type", "", "filter by type")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q := strings.Join(fs.Args(), " ")
	c, err := newClient()
	if err != nil {
		return err
	}
	secrets, err := c.Search(q, *tag, *typ)
	if err != nil {
		return err
	}
	for _, sec := range secrets {
		printSecret(sec, false)
	}
	return nil
}

func cmdDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: vault delete <name>")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.Delete(fs.Arg(0)); err != nil {
		return err
	}
	fmt.Printf("deleted %s\n", fs.Arg(0))
	return nil
}

func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	limit := fs.Int("limit", 50, "max entries")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	rows, err := c.Audit(*limit)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}

func cmdToken(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vault token create --label <label>")
	}
	switch args[0] {
	case "create":
		return cmdTokenCreate(args[1:])
	default:
		return fmt.Errorf("unknown token subcommand %q", args[0])
	}
}

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	outPath := *out
	if outPath == "" {
		outPath = defaultSnapshotFilename()
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	if err := c.DownloadSnapshot(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("snapshot written to %s\n", outPath)
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	in := fs.String("in", "", "snapshot file path")
	dataDir := fs.String("data-dir", "./data", "vault data directory")
	force := fs.Bool("force", false, "overwrite existing vault.db")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	if err := backup.RestoreSnapshotFile(*in, *dataDir, *force); err != nil {
		return err
	}
	fmt.Printf("snapshot restored to %s\n", *dataDir)
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	passphrase := fs.String("passphrase", "", "backup passphrase")
	out := fs.String("out", "", "output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pass := *passphrase
	if pass == "" {
		fmt.Fprint(os.Stderr, "Backup passphrase: ")
		var err error
		pass, err = readPassphrase()
		if err != nil {
			return err
		}
	}
	outPath := *out
	if outPath == "" {
		outPath = defaultExportFilename()
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	if err := c.DownloadExport(pass, f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("export written to %s\n", outPath)
	return nil
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	passphrase := fs.String("passphrase", "", "backup passphrase")
	in := fs.String("in", "", "export file path")
	overwrite := fs.Bool("overwrite", false, "overwrite existing secrets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	pass := *passphrase
	if pass == "" {
		fmt.Fprint(os.Stderr, "Backup passphrase: ")
		var err error
		pass, err = readPassphrase()
		if err != nil {
			return err
		}
	}
	blob, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	records, err := backup.OpenExport(pass, blob)
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	created, skipped, overwritten, err := c.ImportSecrets(records, *overwrite)
	if err != nil {
		return err
	}
	fmt.Printf("import complete: %d created, %d skipped, %d overwritten\n", created, skipped, overwritten)
	return nil
}

func cmdTokenCreate(args []string) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	label := fs.String("label", "", "token label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *label == "" {
		return fmt.Errorf("--label is required")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	token, outLabel, err := c.CreateToken(*label)
	if err != nil {
		return err
	}
	fmt.Printf("token: %s\nlabel: %s\n", token, outLabel)
	return nil
}

func defaultSnapshotFilename() string {
	return fmt.Sprintf("agent-vault-%s.avs.tar.gz", timestampForFilename())
}

func defaultExportFilename() string {
	return fmt.Sprintf("agent-vault-%s.ave", timestampForFilename())
}

func timestampForFilename() string {
	return time.Now().Format("20060102-150405")
}

func newClient() (*client.Client, error) {
	baseURL := envOr("AGENT_VAULT_URL", "http://localhost:8200")
	token := os.Getenv("AGENT_VAULT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("AGENT_VAULT_TOKEN is required")
	}
	return client.New(baseURL, token), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printSecret(sec vault.Secret, reveal bool) {
	if reveal {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]interface{}{
			"name":       sec.Name,
			"type":       sec.Type,
			"secret":     sec.Secret,
			"username":   sec.Username,
			"url":        sec.URL,
			"tags":       sec.Tags,
			"notes":      sec.Notes,
			"metadata":   sec.Metadata,
			"created_at": sec.CreatedAt,
			"updated_at": sec.UpdatedAt,
			"version":    sec.Version,
		})
		return
	}
	fmt.Printf("%s (%s)\n", sec.Name, sec.Type)
}

func readPassphrase() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(pass), nil
	}

	pass, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(pass, "\r\n"), nil
}
