# Caddy config volume

The `caddy-config` Docker volume is **generated at runtime** by agent-vault when you save Settings (hostname / HTTPS). The vault writes `Caddyfile` into the shared volume root.

**Do not commit or hand-edit Caddy config in this repo.** Configure TLS via the Admin UI Settings page, then start the optional Compose profile:

```bash
docker compose --profile https up -d
```

Caddy reads `/etc/caddy/Caddyfile` from the same volume (mounted read-only). Private HTTP access on host port `8200` is unchanged.
