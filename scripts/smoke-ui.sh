#!/usr/bin/env bash
set -euo pipefail

DIR=$(mktemp -d)
DATA_DIR="$DIR/data"
BIN_DIR="$DIR/bin"
JAR="$DIR/cookies.txt"
REVEAL_FILE="$DIR/reveal.json"
LIST_FILE="$DIR/list.json"
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

"$BIN_DIR/vault" init --data-dir "$DATA_DIR" --passphrase 'ui-smoke-pass' >/dev/null

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
BASE="http://localhost:$PORT"

AGENT_VAULT_DATA_DIR="$DATA_DIR" PORT="$PORT" "$BIN_DIR/vault-server" &
PID=$!

for _ in $(seq 1 30); do
  if curl -sf "$BASE/health" | grep -q '"sealed":false'; then
    break
  fi
  sleep 0.2
done
curl -sf "$BASE/health" | grep -q '"sealed":false'

csrf_from_jar() {
  awk -F'\t' '$6=="agent_vault_csrf" {print $7}' "$JAR" | tail -1
}

# login
curl -sf -c "$JAR" -b "$JAR" -X POST "$BASE/ui/login" \
  -H 'Content-Type: application/json' \
  -d '{"passphrase":"ui-smoke-pass"}' | grep -q '"ok":true'

CSRF=$(csrf_from_jar)
if [[ -z "$CSRF" ]]; then
  echo "smoke-ui: missing CSRF cookie" >&2
  exit 1
fi

SECRET_NAME="ui.smoke.test"
SECRET_VALUE="sk-ui-smoke-secret-value"

# create
curl -sf -c "$JAR" -b "$JAR" -X POST "$BASE/ui/api/secrets" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" \
  -d "{\"name\":\"$SECRET_NAME\",\"type\":\"api_key\",\"secret\":\"$SECRET_VALUE\",\"tags\":[\"smoke\",\"ui\"]}" \
  | grep -q "\"name\":\"$SECRET_NAME\""

# reveal (assert without printing secret material)
REVEAL_STATUS=$(curl -s -o "$REVEAL_FILE" -w '%{http_code}' -b "$JAR" \
  "$BASE/ui/api/secrets/$SECRET_NAME?reveal=1")
if [[ "$REVEAL_STATUS" != "200" ]]; then
  echo "smoke-ui: reveal failed status $REVEAL_STATUS" >&2
  exit 1
fi

# list must not include secret values
curl -sf -b "$JAR" -o "$LIST_FILE" "$BASE/ui/api/secrets"

python3 - "$SECRET_NAME" "$SECRET_VALUE" "$REVEAL_FILE" "$LIST_FILE" <<'PY'
import json
import sys

name, secret_value, reveal_path, list_path = sys.argv[1:5]

with open(reveal_path, encoding="utf-8") as f:
    revealed = json.load(f)
if revealed.get("secret") != secret_value:
    print("smoke-ui: reveal response missing expected secret", file=sys.stderr)
    sys.exit(1)

with open(list_path, encoding="utf-8") as f:
    items = json.load(f)

names = []
for item in items:
    if "secret" in item:
        print("smoke-ui: list must not include secret field", file=sys.stderr)
        sys.exit(1)
    if "username" in item:
        print("smoke-ui: list must not include username field", file=sys.stderr)
        sys.exit(1)
    names.append(item.get("name"))

if name not in names:
    print("smoke-ui: created secret not in list", file=sys.stderr)
    sys.exit(1)
PY

# logout
curl -sf -c "$JAR" -b "$JAR" -X POST "$BASE/ui/logout" | grep -q '"ok":true'

echo "smoke-ui: OK"
