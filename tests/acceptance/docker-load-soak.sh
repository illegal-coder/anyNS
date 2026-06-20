#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GPGSQL_COMPOSE="$ROOT/docker-compose.gpgsql.yml"
PRIVATE_CA_COMPOSE="$ROOT/tests/docker/compose.private-ca.yml"
PROJECT="${ANYNS_LOAD_SOAK_PROJECT:-anyns-load-soak}"
TMP_DIR="$(mktemp -d)"
ITERATIONS="${ANYNS_LOAD_SOAK_ITERATIONS:-40}"
CERT_COUNT="${ANYNS_LOAD_SOAK_CERTS:-3}"

export COMPOSE_PROFILES=acceptance
export ANYNS_ADMIN_BUILD_CONTEXT="$ROOT"
export ANYNS_PRIVATE_CA_CONFIG_PATH="$ROOT/tests/docker/anyns-private-ca-config.json"
export PDNS_POSTGRES_DB=pdns
export PDNS_POSTGRES_USER=pdns
export PDNS_POSTGRES_PASSWORD=load-soak-password
export PDNS_AUTH_API_KEY=load-soak-api-key
export PDNS_AUTH_WEBSERVER_PASSWORD=load-soak-web-password
export PDNS_POSTGRES_DATA="$TMP_DIR/postgres"
export PDNS_GPGSQL_DNS_PORT="${ANYNS_LOAD_SOAK_DNS_PORT:-15331}"
export PDNS_GPGSQL_API_PORT="${ANYNS_LOAD_SOAK_API_PORT:-18093}"
export ANYNS_PRIVATE_CA_ADMIN_PORT="${ANYNS_LOAD_SOAK_ADMIN_PORT:-28093}"
export NO_PROXY="${NO_PROXY:+${NO_PROXY},}127.0.0.1,localhost"
export no_proxy="${no_proxy:+${no_proxy},}127.0.0.1,localhost"

cd "$ROOT"

for command in docker curl python3 grep; do
  command -v "$command" >/dev/null || {
    echo "SKIP: $command is not installed"
    exit 0
  }
done
if ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon is not available"
  exit 0
fi
docker compose version >/dev/null

compose() {
  docker compose -p "$PROJECT" -f "$GPGSQL_COMPOSE" -f "$PRIVATE_CA_COMPOSE" "$@"
}

cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

wait_admin() {
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$ANYNS_PRIVATE_CA_ADMIN_PORT/healthz" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

poll_job() {
  local job_id="$1"
  for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:$ANYNS_PRIVATE_CA_ADMIN_PORT/api/v1/certificates/orders/$job_id" >/tmp/anyns-load-soak-job.json
    status="$(python3 -c 'import json; print(json.load(open("/tmp/anyns-load-soak-job.json"))["status"])')"
    if [[ "$status" == "issued" ]]; then
      return 0
    fi
    if [[ "$status" == "failed" ]]; then
      cat /tmp/anyns-load-soak-job.json
      return 1
    fi
    sleep 1
  done
  cat /tmp/anyns-load-soak-job.json
  return 1
}

resource_snapshot() {
  local label="$1"
  echo "resource-$label"
  date -Is
  uptime
  free -h
  df -h /
  container_ids="$(compose ps -q)"
  if [[ -n "$container_ids" ]]; then
    docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.BlockIO}}' $container_ids
  fi
  compose ps
}

query_www() {
  compose exec -T dns-tools \
    dig +short +time=2 +tries=1 @pdns-authoritative -p 5300 www.anyns.test A
}

assert_api_zone() {
  curl -fsS \
    -H "X-API-Key: $PDNS_AUTH_API_KEY" \
    "http://127.0.0.1:$PDNS_GPGSQL_API_PORT/api/v1/servers/localhost/zones/anyns.test." \
    | grep -q '"name"[[:space:]]*:[[:space:]]*"anyns.test."'
}

compose config --quiet

if [[ "${ANYNS_RUN_DOCKER_LOAD_SOAK:-1}" != "1" ]]; then
  echo "Docker load/soak compose config passed; runtime execution disabled"
  exit 0
fi

mkdir -p "$PDNS_POSTGRES_DATA"
compose pull --policy always pdns-postgres pdns-authoritative pdns-authoritative-init
compose build --pull dns-tools admin
compose up -d --wait
wait_admin

echo "phase:baseline"
test "$(query_www)" = "192.0.2.53"
assert_api_zone
curl -fsS "http://127.0.0.1:$ANYNS_PRIVATE_CA_ADMIN_PORT/api/v1/certificates/orders" >/tmp/anyns-load-soak-orders.json
resource_snapshot "baseline"

echo "phase:dns-api-loop"
compose exec -T dns-tools sh -s -- "$ITERATIONS" <<'SH'
set -eu
iterations="$1"
for i in $(seq 1 "$iterations"); do
  test "$(dig +short +time=2 +tries=1 @pdns-authoritative -p 5300 www.anyns.test A)" = "192.0.2.53"
done
SH
for _ in $(seq 1 "$ITERATIONS"); do
  curl -fsS "http://127.0.0.1:$ANYNS_PRIVATE_CA_ADMIN_PORT/healthz" >/dev/null
  assert_api_zone
done

echo "phase:certificate-batch"
for index in $(seq 1 "$CERT_COUNT"); do
  curl -fsS -X POST "http://127.0.0.1:$ANYNS_PRIVATE_CA_ADMIN_PORT/api/v1/certificates/orders" \
    -H 'Content-Type: application/json' \
    --data "{\"domains\":[\"load-$index.privateca.hns\",\"load-$index\"],\"idempotency_key\":\"load-soak-$index\"}" \
    >/tmp/anyns-load-soak-order.json
  job_id="$(python3 -c 'import json; print(json.load(open("/tmp/anyns-load-soak-order.json"))["id"])')"
  poll_job "$job_id"
done

curl -fsS "http://127.0.0.1:$ANYNS_PRIVATE_CA_ADMIN_PORT/api/v1/certificates/orders" >/tmp/anyns-load-soak-orders.json
python3 - "$CERT_COUNT" <<'PY'
import json
import sys

wanted = int(sys.argv[1])
jobs = json.load(open("/tmp/anyns-load-soak-orders.json"))
issued = [job for job in jobs if job.get("status") == "issued" and any(name.startswith("load-") for name in job.get("domains", []))]
if len(issued) < wanted:
    raise SystemExit(f"expected at least {wanted} issued load certs, got {len(issued)}")
if any("idempotency_key" in job for job in jobs):
    raise SystemExit("inventory leaked idempotency_key")
PY

echo "phase:post-check"
test "$(query_www)" = "192.0.2.53"
assert_api_zone
curl -fsS "http://127.0.0.1:$ANYNS_PRIVATE_CA_ADMIN_PORT/healthz" >/dev/null
resource_snapshot "post"

echo "Docker load/soak smoke passed"
