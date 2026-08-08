# agent-vault

Encrypted secrets vault for agents.

## HTTP API

Search endpoint: `GET /v1/search` (query params `q`, `tag`, `type`). This path replaces `GET /v1/secrets:search` from the design doc for Go 1.22 `ServeMux` compatibility.
