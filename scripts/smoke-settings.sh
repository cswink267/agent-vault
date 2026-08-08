#!/usr/bin/env bash
set -euo pipefail

DIR=$(mktemp -d)
DATA_DIR="$DIR/data"
CADDY_DIR="$DIR/caddy"
BIN_DIR="$DIR/bin"
JAR="$DIR/cookies.txt"
SETTINGS_FILE="$DIR/settings.json"
CADDYFILE="$CADDY_DIR/Caddyfile"
mkdir -p "$BIN_DIR" "$CADDY_DIR"

# Sensitive values — never echo these
PASSPHRASE='settings-smoke-pass'
HOSTNAME='vault.example.test'

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

"$BIN_DIR/vault" init --data-dir "$DATA_DIR" --passphrase "$PASSPHRASE" >/dev/null

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
BASE="http://localhost:$PORT"

AGENT_VAULT_DATA_DIR="$DATA_DIR" \
AGENT_VAULT_CADDY_CONFIG_DIR="$CADDY_DIR" \
PORT="$PORT" \
"$BIN_DIR/vault-server" &
PID=$!

for _ in $(seq 1 30); do
  if curl -sf "$BASE/health" | grep -q '"ok":true'; then
    break
  fi
  sleep 0.2
done
curl -sf "$BASE/health" | grep -q '"ok":true'

csrf_from_jar() {
  awk -F'\t' '$6=="agent_vault_csrf" {print $7}' "$JAR" | tail -1
}

curl -sf -c "$JAR" -b "$JAR" -X POST "$BASE/ui/login" \
  -H 'Content-Type: application/json' \
  -d "{\"passphrase\":\"$PASSPHRASE\"}" | grep -q '"ok":true'

CSRF=$(csrf_from_jar)
if [[ -z "$CSRF" ]]; then
  echo "smoke-settings: missing CSRF cookie" >&2
  exit 1
fi

PUT_STATUS=$(curl -s -o "$SETTINGS_FILE" -w '%{http_code}' -c "$JAR" -b "$JAR" \
  -X PUT "$BASE/ui/api/settings" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" \
  -d "{\"public_hostname\":\"$HOSTNAME\",\"https_enabled\":true}")
if [[ "$PUT_STATUS" != "200" ]]; then
  echo "smoke-settings: PUT settings failed status $PUT_STATUS" >&2
  exit 1
fi

if [[ ! -f "$CADDYFILE" ]]; then
  echo "smoke-settings: Caddyfile not written" >&2
  exit 1
fi

python3 - "$HOSTNAME" "$CADDYFILE" <<'PY'
import sys

hostname, path = sys.argv[1:3]
with open(path, encoding="utf-8") as f:
    content = f.read()
if hostname not in content:
    print("smoke-settings: Caddyfile missing hostname", file=sys.stderr)
    sys.exit(1)
if "reverse_proxy agent-vault:8080" not in content:
    print("smoke-settings: Caddyfile missing reverse_proxy agent-vault:8080", file=sys.stderr)
    sys.exit(1)
PY

GET_STATUS=$(curl -s -o "$SETTINGS_FILE" -w '%{http_code}' -b "$JAR" "$BASE/ui/api/settings")
if [[ "$GET_STATUS" != "200" ]]; then
  echo "smoke-settings: GET settings failed status $GET_STATUS" >&2
  exit 1
fi

python3 - "$HOSTNAME" "$SETTINGS_FILE" <<'PY'
import json
import sys

hostname, path = sys.argv[1:3]
with open(path, encoding="utf-8") as f:
    body = json.load(f)
if body.get("public_hostname") != hostname:
    print("smoke-settings: GET public_hostname mismatch", file=sys.stderr)
    sys.exit(1)
if body.get("https_enabled") is not True:
    print("smoke-settings: GET https_enabled not true", file=sys.stderr)
    sys.exit(1)
if body.get("caddyfile_status") != "active":
    print("smoke-settings: GET caddyfile_status not active", file=sys.stderr)
    sys.exit(1)
if body.get("public_base_url") != f"https://{hostname}":
    print("smoke-settings: GET public_base_url mismatch", file=sys.stderr)
    sys.exit(1)
PY

echo "smoke-settings: OK"
