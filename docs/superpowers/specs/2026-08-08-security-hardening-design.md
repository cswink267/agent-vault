# Agent Vault Security Hardening — Design Spec

## Goal

Close the highest-risk findings from the post–Phase 2c security audit without redesigning the single-tenant trust model.

## In scope

1. **Auth abuse resistance** — rate limit + lockout on passphrase login/unlock; bound concurrent Argon2 derivations
2. **Passphrase strength** — minimum length (≥12) at init, change-passphrase, and backup export
3. **HTTP hardening** — security headers, `Cache-Control: no-store` on secret-bearing responses, server timeouts, request body size limit
4. **Operational hygiene** — stop logging root token; strip sealed state from unauthenticated `/health`; bind address configurable
5. **Backup gate** — refuse snapshot while sealed (export already gated)
6. **Audit** — attribute `settings_update` to the UI/API actor

## Out of scope (follow-ups)

- Token scopes / per-token revoke
- Encrypting snapshot so `unseal.key` is not plaintext in the archive
- IP allowlists / SSO
- Defaulting Docker publish away from `0.0.0.0` (document LAN risk; bind via env)

## Defaults

| Control | Default |
|---------|---------|
| Min passphrase length | 12 |
| Login/unlock attempts per IP | 5 / 15 minutes |
| Concurrent KDF | 2 |
| Max JSON body | 1 MiB |
| Trust `X-Forwarded-For` | off (`AGENT_VAULT_TRUST_PROXY=1` to enable) |
| Listen | `AGENT_VAULT_BIND` or `0.0.0.0` (Docker) |

## Success criteria

- Brute-force login returns 429 after threshold; tests cover it
- Short passphrases rejected at init/change/export
- Security headers present on API + UI responses
- `go test ./...` and existing smokes pass
