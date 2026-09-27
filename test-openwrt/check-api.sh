#!/bin/sh
set -eu
BASE=http://127.0.0.1:5000

echo "===== static UI ====="
wget -qO- "$BASE/" | grep -q 'Родительский контроль'
echo "OK: index.html"

echo "===== HTTP API is intentionally disabled ====="
if wget -qO- "$BASE/api/health" >/tmp/pc-http-api.out 2>/dev/null; then
  echo "ERROR: /api/health unexpectedly succeeded over HTTP"
  exit 1
fi
echo "OK: direct HTTP API rejected"

echo "===== WebSocket handshake ====="
REQ='GET /ws HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n'
RESP="$(printf "$REQ" | nc -w 2 127.0.0.1 5000 2>/dev/null || true)"
printf '%s\n' "$RESP" | grep -q '101 Switching Protocols'
echo "OK: WebSocket upgrade"
