# CLI reference (`vault`)

The `vault` binary is the everyday tool for scripts, SSH sessions, and agents that have a shell. Most commands talk to a running server over HTTP. Exceptions: `init` and `restore` work on the local filesystem.

## Environment

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `AGENT_VAULT_URL` | for remote cmds | `http://localhost:8200` | API base (use `https://…` when HTTPS is on) |
| `AGENT_VAULT_TOKEN` | for remote cmds | — | Bearer token (`admin` or `agent`) |

```bash
export AGENT_VAULT_URL=http://localhost:8200   # or http://<hostname>:8200
export AGENT_VAULT_TOKEN=avt_…
```

Put those in your shell profile or the agent’s MCP/env config—not in a git-tracked file.

## Commands

### `vault init`

Create a new local vault directory (no server required).

```bash
vault init --data-dir ./data --passphrase 'at-least-12-chars'
```

Writes `vault.db`, `unseal.key`, and `root.token`. Prints the root token once—save it.

### `vault unlock` / `vault lock`

```bash
vault unlock --passphrase '…'
vault lock
```

`lock` requires **admin** scope. `unlock` works for any authenticated token (agent or admin).

### `vault set`

Create or update a secret.

```bash
vault set \
  --name openai.api_key \
  --type api_key \
  --secret 'sk-…' \
  --tags agents,openai \
  --username '' \
  --url '' \
  --notes ''
```

| Flag | Required | Notes |
|------|----------|-------|
| `--name` | yes | Unique slug |
| `--type` | yes | `api_key` \| `login` \| `ssh_key` \| `token` \| `note` |
| `--secret` | yes | Secret value |
| `--username` | no | Useful for `login` |
| `--url` | no | |
| `--tags` | no | Comma-separated |
| `--notes` | no | |

### `vault get` / `list` / `search` / `delete`

```bash
vault get openai.api_key          # reveals secret (JSON)
vault list                        # metadata only
vault search openai               # positional query
vault search --tag agents
vault search --type api_key
vault delete openai.api_key
```

### `vault audit`

```bash
vault audit                 # recent events (admin)
vault audit --limit 100
```

### `vault token`

```bash
# Mint (admin). Default scope is agent.
vault token create --label my-bot --scope agent
vault token create --label break-glass --scope admin

vault token list
vault token revoke --id <uuid>
```

### `vault change-passphrase` / `rotate-master`

```bash
vault change-passphrase --old 'current…' --new 'replacement…'
vault rotate-master --passphrase 'current…'
```

Both revoke all tokens and return a new root token once. Admin only. Remint agent tokens afterward.

### `vault backup` / `restore`

Encrypted **AVS2** snapshot (database + unseal key). Passphrase required (≥12 characters).

```bash
vault backup --passphrase 'snapshot-pass…' --out vault.avs
vault restore --in vault.avs --passphrase 'snapshot-pass…' --data-dir ./data [--force]
```

- Stop the server before restoring onto a live data directory.
- Legacy plaintext gzip snapshots (`.avs.tar.gz`) still restore; passphrase is optional for those only.

### `vault export` / `import`

Portable encrypted secret dump (no unseal key).

```bash
vault export --passphrase 'export-pass…' --out secrets.ave
vault import --passphrase 'export-pass…' --in secrets.ave [--overwrite]
```

Vault must be **unsealed** for export. Import merges into the current vault.

## Exit behavior and output

- Most commands print JSON to stdout for machine use (`get`, `list`, `search`, `audit`, `token list`).
- Errors go to stderr with a non-zero exit code.
- Avoid putting `--secret` or passphrases on a command line that will land in shell history—prefer env injection from a secret manager when you can.

## Everyday examples

```bash
# Store what the user just pasted
vault set --name github.token --type token --secret "$TOKEN" --tags github,ci

# Find then reveal
vault search github
vault get github.token

# Operator: mint a token for a new agent
vault token create --label windsurf --scope agent
```
