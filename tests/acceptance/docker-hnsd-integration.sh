#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/tests/docker/compose.hnsd.yml"
INTEGRATION_CONFIG="$ROOT/tests/docker/anyns-hnsd-config.json"
PROJECT="${ANYNS_DOCKER_HNSD_PROJECT:-anyns-hnsd-integration}"
TEST_QNAME="${ANYNS_HNSD_TEST_QNAME:-example.hns}"
BACKEND_QNAME="${ANYNS_HNSD_BACKEND_QNAME:-example.}"

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

if [[ "${ANYNS_RUN_DOCKER_HNSD_INTEGRATION:-0}" != "1" ]]; then
  echo "docker hnsd integration compose config passed; live hnsd runtime execution disabled"
  exit 0
fi

cleanup() {
  if [[ "${ANYNS_KEEP_DOCKER_HNSD_INTEGRATION:-}" != "1" ]]; then
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --build

tools() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T dns-tools sh -lc "$*"
}

for _ in $(seq 1 90); do
  if tools 'curl -fsS http://anyns-plugin-runtime:8081/healthz >/dev/null && dig +time=1 +tries=1 @bind-latest version.bind TXT CH >/dev/null' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! tools 'curl -fsS http://anyns-plugin-runtime:8081/healthz >/dev/null && dig +time=1 +tries=1 @bind-latest version.bind TXT CH >/dev/null'; then
  echo "FAIL: anyns runtime did not become healthy"
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" logs --no-color anyns-plugin-runtime hnsd pdns-recursor bind-latest || true
  exit 1
fi

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"'"$TEST_QNAME"'\",\"qtype\":\"A\",\"context\":{\"trace_id\":\"docker-hnsd-live\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-hnsd.json'
tools 'grep -q "\"source_plugin\":\"hns\"" /tmp/runtime-hnsd.json'
tools 'grep -Eq "\"rcode\":\"(NOERROR|NXDOMAIN|SERVFAIL)\"" /tmp/runtime-hnsd.json'
tools 'if grep -q "\"backend_query_name\":" /tmp/runtime-hnsd.json; then grep -q "\"backend_query_name\":\"'"$BACKEND_QNAME"'\"" /tmp/runtime-hnsd.json; fi'
tools '! grep -q "static-hns-fixture" /tmp/runtime-hnsd.json'

tools 'dig +time=3 +tries=1 @pdns-recursor '"$TEST_QNAME"' A | tee /tmp/pdns-hnsd.txt'
tools 'grep -Eq "status: NOERROR|status: NXDOMAIN|status: SERVFAIL" /tmp/pdns-hnsd.txt'
tools 'dig +time=3 +tries=1 @bind-latest '"$TEST_QNAME"' A | tee /tmp/bind-hnsd.txt'
tools 'grep -Eq "status: NOERROR|status: NXDOMAIN|status: SERVFAIL" /tmp/bind-hnsd.txt'
tools 'kdig -p 853 +tls-ca=/certs/ca.crt +tls-hostname=bind-latest @bind-latest '"$TEST_QNAME"' A | tee /tmp/bind-dot-hnsd.txt'
tools 'grep -Eq "status: NOERROR|status: NXDOMAIN|status: SERVFAIL" /tmp/bind-dot-hnsd.txt'
tools 'kdig +https=/dns-query +tls-ca=/certs/ca.crt +tls-hostname=bind-latest @bind-latest '"$TEST_QNAME"' A | tee /tmp/bind-doh-hnsd.txt'
tools 'grep -Eq "status: NOERROR|status: NXDOMAIN|status: SERVFAIL" /tmp/bind-doh-hnsd.txt'

echo "docker hnsd integration passed"
