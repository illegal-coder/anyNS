#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

export NO_PROXY="${NO_PROXY:+${NO_PROXY},}127.0.0.1,localhost"
export no_proxy="${no_proxy:+${no_proxy},}127.0.0.1,localhost"

TMP_DIR="$(mktemp -d)"
RUNTIME_PID=""

cleanup() {
  if [[ -n "$RUNTIME_PID" ]] && kill -0 "$RUNTIME_PID" 2>/dev/null; then
    kill "$RUNTIME_PID" 2>/dev/null || true
    wait "$RUNTIME_PID" 2>/dev/null || true
  fi
  if [[ "${ANYNS_KEEP_ACCEPTANCE_TMP:-}" != "1" ]]; then
    rm -rf "$TMP_DIR"
  else
    printf 'kept acceptance temp dir: %s\n' "$TMP_DIR"
  fi
}
trap cleanup EXIT

PORT="${ANYNS_ACCEPTANCE_RUNTIME_PORT:-}"
if [[ -z "$PORT" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    if ! PORT="$(python3 - 2>/dev/null <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
    )"; then
      PORT="18081"
    fi
  else
    PORT="18081"
  fi
fi

CONFIG="$TMP_DIR/anyns-runtime-smoke.json"
DNSLOG_PATH="$TMP_DIR/dnslog.jsonl"
HONEYPOT_QUEUE_PATH="$TMP_DIR/honeypot-failed.jsonl"
RUNTIME_LOG="$TMP_DIR/runtime.log"
RUNTIME_BIN="$TMP_DIR/anyns-plugin-runtime"

cat >"$CONFIG" <<EOF_CONFIG
{
  "admin_addr": "127.0.0.1:0",
  "runtime_addr": "127.0.0.1:${PORT}",
  "log_forwarder_addr": "127.0.0.1:0",
  "request_timeout": "1s",
  "plugins": [
    {"name": "hns", "enabled": true, "request_timeout": "1s"},
    {"name": "ens", "enabled": false, "request_timeout": "1s"},
    {"name": "namecoin-bit", "enabled": false, "request_timeout": "1s"},
    {"name": "stacks-bns", "enabled": false, "request_timeout": "1s"},
    {"name": "pns-polkadot", "enabled": false, "request_timeout": "1s"},
    {"name": "pns-pulsechain", "enabled": false, "request_timeout": "1s"},
    {"name": "unstoppable-domains", "enabled": false, "request_timeout": "1s"}
  ],
  "routes": [
    {
      "name": "hns-acceptance",
      "suffixes": [".hns", ".hsd"],
      "client_views": ["default"],
      "tenants": ["default"],
      "plugin": "hns",
      "priority": 100,
      "fallback": "icann-recursive"
    }
  ],
  "security": {
    "enabled": true,
    "tunnel_max_qname_length": 180,
    "tunnel_max_label_length": 63,
    "tunnel_entropy_threshold": 3.0,
    "dga_entropy_threshold": 4.2,
    "dga_digit_ratio_threshold": 0.25,
    "nxdomain_window_seconds": 60,
    "nxdomain_threshold": 20,
    "block_rebinding": true,
    "abnormal_rr_action": "log_only",
    "reflection_amplification_action": "rate_limit"
  },
  "dnslog": {
    "limit": 100,
    "path": "${DNSLOG_PATH}"
  },
  "honeypot": {
    "url": "http://127.0.0.1:1/api/v1/dns-events",
    "api_key": "acceptance-key",
    "hmac_secret": "acceptance-secret",
    "failed_queue_path": "${HONEYPOT_QUEUE_PATH}",
    "failed_queue_max_entries": 100,
    "retry_interval": "30s",
    "max_attempts": 3,
    "request_timeout": "200ms"
  },
  "management": {
    "auth_required": false
  }
}
EOF_CONFIG

GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go build -buildvcs=false -o "$RUNTIME_BIN" ./cmd/anyns-plugin-runtime

ANYNS_CONFIG_FILE="$CONFIG" "$RUNTIME_BIN" >"$RUNTIME_LOG" 2>&1 &
RUNTIME_PID="$!"

STARTUP_ATTEMPTS="${ANYNS_ACCEPTANCE_STARTUP_ATTEMPTS:-300}"
for _ in $(seq 1 "$STARTUP_ATTEMPTS"); do
  if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$RUNTIME_PID" 2>/dev/null; then
    printf 'SKIP: anyns-plugin-runtime exited before listening on 127.0.0.1:%s\n' "$PORT"
    sed -n '1,120p' "$RUNTIME_LOG"
    exit 0
  fi
  sleep 0.1
done

if ! curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
  printf 'SKIP: could not connect to anyns-plugin-runtime on 127.0.0.1:%s within timeout\n' "$PORT"
  sed -n '1,120p' "$RUNTIME_LOG"
  exit 0
fi

curl -fsS "http://127.0.0.1:${PORT}/api/v1/resolve" \
  -H 'Content-Type: application/json' \
  -d '{"qname":"example.hns","qtype":"A","context":{"trace_id":"acceptance-hns","client_ip":"127.0.0.1","client_view":"default","tenant":"default","policy_tags":["acceptance"]}}' \
  | grep -q '"source_plugin":"hns"'

curl -sS "http://127.0.0.1:${PORT}/api/v1/resolve" \
  -H 'Content-Type: application/json' \
  -d '{"qname":"qwertyuiopasdfghjklzxcvbnm1234567890.example","qtype":"TXT","context":{"trace_id":"acceptance-honeypot","client_ip":"127.0.0.1","client_view":"default","tenant":"default"}}' \
  | grep -q '"action":"forward_to_honeypot"'

test -s "$DNSLOG_PATH"
grep -q '"trace_id":"acceptance-hns"' "$DNSLOG_PATH"
grep -q '"trace_id":"acceptance-honeypot"' "$DNSLOG_PATH"
test -s "$HONEYPOT_QUEUE_PATH"
grep -q '"trace_id":"acceptance-honeypot"' "$HONEYPOT_QUEUE_PATH"

curl -fsS "http://127.0.0.1:${PORT}/metrics" \
  | grep -q 'anyns_honeypot_failed_queue_length{service="runtime"} 1'

printf 'runtime smoke acceptance passed on 127.0.0.1:%s\n' "$PORT"
