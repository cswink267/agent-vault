# Phase 2b Backup/Export Final Fix Report

## Changes

- Changed UI snapshot download from `GET /ui/api/backup/snapshot` to CSRF-protected `POST /ui/api/backup/snapshot`; the UI JavaScript now posts and the old GET API path returns 405 instead of falling through to the UI page route.
- Kept `/v1/backup/snapshot` as bearer-authenticated GET for agents and CLI.
- Hardened snapshot extraction to stage archive members, validate all required files and manifest metadata, and only then install files into the destination.
- Updated restore to extract into a temporary directory first, refuse existing `vault.db` without `--force` before writing destination files, install validated `vault.db` and `unseal.key`, and remove stale destination `root.token`.
- Added `.ave` v1 header fields after `AVE1` for Argon2id parameters: header version, time, memory KiB, threads, salt length/salt, nonce length/nonce, then ciphertext.
- Updated the vault CLI default remote URL and help text from `http://localhost:8080` to `http://localhost:8200`.

## Test Results

- `go test ./...` - PASS
- `bash scripts/smoke-backup.sh` - PASS
- `bash scripts/smoke.sh` - PASS
- `bash scripts/smoke-ui.sh` - PASS

## Smoke Output Secret Check

The required smoke commands did not print configured secret values in stdout.

## Commits

- `854d28f fix(backup): harden restore, CSRF snapshot download, and export header`
- `e8d41fe fix(ui): reject GET snapshot downloads`
# Phase 2a Admin UI — Final Fix Report

## Summary

Fixed the secret edit flow when Reveal was not clicked first, improved login and type-picker UX, and removed external Google Fonts requests.

## Changes

### Edit flow (`internal/ui/static/app.js`)
- Edit button auto-fetches `GET /ui/api/secrets/{name}?reveal=1` when the secret is not yet revealed.
- Populates the edit form with the revealed secret/username before showing the form.
- Shows an info message: "Secret revealed for editing."
- Disables Edit briefly while the reveal request is in flight.

### Login vault status (`login.html`, `app.js`, `app.css`)
- On login page load, calls public `GET /health` and displays "Vault status: Sealed" or "Unsealed".

### Type picker (`new.html`, `detail.html`)
- Replaced free-text type inputs with `<select>` options: `api_key`, `login`, `ssh_key`, `token`, `note`.

### Privacy / fonts (`layout.html`, `app.css`)
- Removed Google Fonts `<link>` tags from the shared head template.
- Font stack: `"IBM Plex Sans", "Source Sans 3", "Helvetica Neue", sans-serif` (system fallbacks only).

### Tests (`internal/ui/handlers_test.go`)
- Added `TestUIUpdateWithRevealedPayload`: PUT with empty secret after non-reveal GET is rejected (400); PUT with full revealed payload succeeds and preserves secret.

## Test Results

| Command | Result |
|---------|--------|
| `go test ./...` | PASS |
| `bash scripts/smoke-ui.sh` | PASS (no secret material printed) |
| `bash scripts/smoke.sh` | PASS |

## Notes

- No vault `Put` preserve-on-empty semantics were added; the JS auto-reveal path is the primary fix.
- `/health` on the login page requires the combined vault-server handler (not UI-only test server); failures are ignored silently.
