# Final Important Findings Fix Report

## Changes

- Added a persisted `master_check` HMAC verifier for the generated master key during vault initialization.
- Updated unlock-by-key, unlock-by-passphrase, and auto-unseal paths to verify the master key before assigning it to the vault.
- Added CLI passphrase prompting with `golang.org/x/term.ReadPassword` for TTY stdin and a non-echo line-reading fallback for non-TTY stdin.
- Added audit records for successful API unlock, lock, and vault search operations.
- Added `Vault.Create` and changed `POST /v1/secrets` to use atomic create-only insertion, returning conflict on duplicate names without overwriting existing secrets.
- Added regression tests for wrong unseal keys, unlock/lock/search audit rows, and duplicate POST conflict preservation.

## Tests Run

- `go test ./...`
- `bash scripts/smoke.sh`

## Results

- `go test ./...`: passed.
- `bash scripts/smoke.sh`: passed.
- Smoke output did not contain `avt_` or `Root token`.

## Concerns

- No remaining concerns.
