#!/usr/bin/env bash
set -euo pipefail

DIR=$(mktemp -d)
DATA_DIR="$DIR/data1"
RESTORE_DIR="$DIR/data2"
BIN_DIR="$DIR/bin"
SNAPSHOT="$DIR/snapshot.avs.tar.gz"
EXPORT="$DIR/export.ave"
GET_FILE="$DIR/get.txt"
mkdir -p "$BIN_DIR"

# Sensitive values — never echo these
VAULT_PASS='backup-smoke-vault-pass'
BACKUP_PASS='backup-smoke-export-pass'
SECRET_NAME='backup.smoke.test'
SECRET_VALUE='sk-backup-smoke-secret-value'

cleanup() {
  if [[ -n "${PID:-}" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  if [[ -n "${PID2:-}" ]]; then
    kill "$PID2" 2>/dev/null || true
    wait "$PID2" 2>/dev/null || true
  fi
  rm -rf "$DIR"
}
trap cleanup EXIT

go build -o "$BIN_DIR/vault-server" ./cmd/vault-server
go build -o "$BIN_DIR/vault" ./cmd/vault

"$BIN_DIR/vault" init --data-dir "$DATA_DIR" --passphrase "$VAULT_PASS" >/dev/null

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
  --name "$SECRET_NAME" \
  --type api_key \
  --secret "$SECRET_VALUE" \
  --tags smoke,backup >/dev/null

# CLI backup → restore to other dir → get secret
"$BIN_DIR/vault" backup --out "$SNAPSHOT" >/dev/null
test -s "$SNAPSHOT"

"$BIN_DIR/vault" restore --in "$SNAPSHOT" --data-dir "$RESTORE_DIR" >/dev/null
test -f "$RESTORE_DIR/vault.db"
test -f "$RESTORE_DIR/unseal.key"

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
unset PID

PORT2=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
export AGENT_VAULT_URL="http://localhost:$PORT2"

AGENT_VAULT_DATA_DIR="$RESTORE_DIR" PORT="$PORT2" "$BIN_DIR/vault-server" &
PID2=$!

for _ in $(seq 1 30); do
  if curl -sf "$AGENT_VAULT_URL/health" | grep -q '"ok":true'; then
    break
  fi
  sleep 0.2
done
curl -sf "$AGENT_VAULT_URL/health" | grep -q '"ok":true'

"$BIN_DIR/vault" get "$SECRET_NAME" >"$GET_FILE"
python3 - "$SECRET_VALUE" "$GET_FILE" <<'PY'
import json
import sys

expected, path = sys.argv[1:3]
with open(path, encoding="utf-8") as f:
    got = json.load(f).get("secret")
if got != expected:
    print("smoke-backup: restored vault secret mismatch", file=sys.stderr)
    sys.exit(1)
PY

kill "$PID2" 2>/dev/null || true
wait "$PID2" 2>/dev/null || true
unset PID2

# CLI export → import into same vault after delete
export AGENT_VAULT_URL="http://localhost:$PORT"
AGENT_VAULT_DATA_DIR="$DATA_DIR" PORT="$PORT" "$BIN_DIR/vault-server" &
PID=$!

for _ in $(seq 1 30); do
  if curl -sf "$AGENT_VAULT_URL/health" | grep -q '"ok":true'; then
    break
  fi
  sleep 0.2
done
curl -sf "$AGENT_VAULT_URL/health" | grep -q '"ok":true'

"$BIN_DIR/vault" export --passphrase "$BACKUP_PASS" --out "$EXPORT" >/dev/null
test -s "$EXPORT"

"$BIN_DIR/vault" delete "$SECRET_NAME" >/dev/null

IMPORT_OUT=$("$BIN_DIR/vault" import --passphrase "$BACKUP_PASS" --in "$EXPORT" 2>&1)
echo "$IMPORT_OUT" | grep -q 'import complete: 1 created'

"$BIN_DIR/vault" get "$SECRET_NAME" >"$GET_FILE"
python3 - "$SECRET_VALUE" "$GET_FILE" <<'PY'
import json
import sys

expected, path = sys.argv[1:3]
with open(path, encoding="utf-8") as f:
    got = json.load(f).get("secret")
if got != expected:
    print("smoke-backup: imported secret mismatch", file=sys.stderr)
    sys.exit(1)
PY

echo "smoke-backup: OK"
