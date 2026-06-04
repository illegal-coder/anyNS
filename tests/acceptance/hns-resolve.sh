#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${ANYNS_RUNTIME_URL:-http://127.0.0.1:8081}"
curl -fsS "$BASE_URL/healthz" >/dev/null
curl -fsS "$BASE_URL/api/v1/resolve" \
  -H 'Content-Type: application/json' \
  -d '{"qname":"example.hns","qtype":"A","context":{"trace_id":"acceptance-hns","client_ip":"127.0.0.1","client_view":"default","tenant":"default"}}' |
  grep -q '"source_plugin":"hns"'
