#!/usr/bin/env bash
set -euo pipefail

DIR=$(mktemp -d)
DATA_DIR="$DIR/data"
BIN_DIR="$DIR/bin"
mkdir -p "$BIN_DIR"

cleanup() {
  if [[ -n "${PID:-}" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$DIR"
}
trap cleanup EXIT

go build -o "$BIN_DIR/vault-server" ./cmd/vault-server
go build -o "$BIN_DIR/vault" ./cmd/vault

"$BIN_DIR/vault" init --data-dir "$DATA_DIR" --passphrase 'smoke-passphrase' >/dev/null

TOKEN=$(cat "$DATA_DIR/root.token")
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
export AGENT_VAULT_URL="http://localhost:$PORT"
export AGENT_VAULT_TOKEN="$TOKEN"

AGENT_VAULT_DATA_DIR="$DATA_DIR" PORT="$PORT" "$BIN_DIR/vault-server" &
PID=$!

for _ in $(seq 1 30); do
  if curl -sf "$AGENT_VAULT_URL/health" | grep -q '"ok":true'; then
    break
  fi
  sleep 0.2
done
curl -sf "$AGENT_VAULT_URL/health" | grep -q '"ok":true'

"$BIN_DIR/vault" set \
  --name smoke.test \
  --type api_key \
  --secret 'sk-smoke-test' \
  --tags smoke,test

"$BIN_DIR/vault" get smoke.test | grep -q 'sk-smoke-test'

"$BIN_DIR/vault" search --tag smoke smoke | grep -q 'smoke.test'

echo "smoke: OK"
