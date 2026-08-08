# Contributing

Thanks for helping improve Agent Vault.

## Development

- Go **1.25+**
- Docker + Docker Compose for the recommended deploy path
- Run tests: `go test ./...`
- Smoke scripts live under `scripts/`

## Pull requests

1. Keep changes focused and documented when they affect operators or agents.
2. Prefer tests for API, vault, and UI behavior you change.
3. Do not commit secrets, tokens, local `.agents/` installs, or machine-specific config.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
