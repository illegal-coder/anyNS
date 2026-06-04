#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

HOOK="configs/pdns-recursor/recursor.lua"
test -f "$HOOK"

grep -q 'socket.http' "$HOOK"
grep -q 'ltn12' "$HOOK"
grep -q 'cjson.safe' "$HOOK"
grep -q 'falling back to ICANN recursion' "$HOOK"
grep -q 'ANYNS_RUNTIME_ENDPOINT' "$HOOK"
grep -q 'ANYNS_CLIENT_VIEW' "$HOOK"
grep -q 'ANYNS_TENANT' "$HOOK"
grep -q 'ANYNS_POLICY_TAGS' "$HOOK"
grep -q 'ANYNS_RUNTIME_TIMEOUT_SECONDS' "$HOOK"
grep -q 'policy_tags' "$HOOK"
grep -q 'http.TIMEOUT' "$HOOK"
grep -q 'apply_runtime_result' "$HOOK"
grep -q 'pdns.NXDOMAIN' "$HOOK"
grep -q 'pdns.SERVFAIL' "$HOOK"
grep -q 'suppressing ICANN fallback for routed name' "$HOOK"
if grep -q 'X-anyNS' "$HOOK"; then
  echo "unexpected HTTP header grep matched obsolete signature handling in Lua hook" >&2
  exit 1
fi

if command -v luac >/dev/null 2>&1; then
  luac -p "$HOOK"
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 && test -f .env.example; then
  cleanup_env=0
  if ! test -f .env; then
    cp .env.example .env
    cleanup_env=1
  fi
  cleanup() {
    if [ "$cleanup_env" -eq 1 ]; then
      rm -f .env
    fi
  }
  trap cleanup EXIT
  docker compose --env-file .env.example config >/tmp/anyns-compose-rendered.yml
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "docker compose available but .env.example is absent; skipped compose render check"
else
  echo "docker compose not available; skipped compose render check"
fi
