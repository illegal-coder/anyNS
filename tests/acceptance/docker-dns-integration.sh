#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/tests/docker/compose.dns-integration.yml"
INTEGRATION_CONFIG="$ROOT/tests/docker/anyns-config.json"
PROJECT="${ANYNS_DOCKER_PROJECT:-anyns-dns-integration}"

cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker is not installed"
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon is not available"
  exit 0
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "SKIP: docker compose is not available"
  exit 0
fi

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" config >/dev/null
GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go run -buildvcs=false ./cmd/anyns-config-check "$INTEGRATION_CONFIG" >/dev/null

if [[ "${ANYNS_RUN_DOCKER_DNS_INTEGRATION:-1}" != "1" ]]; then
  echo "docker DNS integration compose config passed; runtime execution disabled"
  exit 0
fi

cleanup() {
  if [[ "${ANYNS_KEEP_DOCKER_DNS_INTEGRATION:-}" != "1" ]]; then
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --build

tools() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T dns-tools sh -lc "$*"
}

tools 'apk add --no-cache bind-tools curl >/dev/null'

for _ in $(seq 1 60); do
  if tools 'curl -fsS http://anyns-plugin-runtime:8081/healthz >/dev/null' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! tools 'curl -fsS http://anyns-plugin-runtime:8081/healthz >/dev/null'; then
  echo "FAIL: anyns runtime did not become healthy"
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" logs --no-color anyns-plugin-runtime backend-fixtures pdns-recursor bind-latest || true
  exit 1
fi

tools 'dig +time=2 +tries=1 @pdns-recursor example.hns A | tee /tmp/pdns-example-hns.txt'
tools 'grep -q "198.51.100" /tmp/pdns-example-hns.txt'

tools 'dig +time=2 +tries=1 @pdns-recursor missing.hns A | tee /tmp/pdns-missing-hns.txt'
tools 'grep -q "status: NXDOMAIN" /tmp/pdns-missing-hns.txt'

tools 'dig +time=2 +tries=1 @pdns-recursor example.bit A | tee /tmp/pdns-example-bit.txt'
tools 'grep -q "198.51.100.77" /tmp/pdns-example-bit.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"www.example.bit\",\"qtype\":\"A\",\"context\":{\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-www-example-bit.json'
tools 'grep -q "198.51.100.78" /tmp/runtime-www-example-bit.json'

tools 'dig +time=2 +tries=1 @bind-latest example.hns A | tee /tmp/bind-example-hns.txt'
tools 'grep -q "198.51.100" /tmp/bind-example-hns.txt'

tools 'dig +time=2 +tries=1 @bind-latest example.com A | tee /tmp/bind-example-com.txt'
tools 'grep -Eq "status: NOERROR|status: SERVFAIL" /tmp/bind-example-com.txt'

tools 'curl -fsS http://anyns-plugin-runtime:8081/api/v1/audit/events?source_plugin=namecoin-bit | tee /tmp/runtime-namecoin-audit.json'
tools 'grep -q "example.bit" /tmp/runtime-namecoin-audit.json'

echo "docker DNS integration passed"
