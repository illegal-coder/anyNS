#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/docker-compose.gpgsql.yml"
PROJECT="${ANYNS_GPGSQL_DOCKER_PROJECT:-anyns-gpgsql-acceptance}"
TMP_DIR="$(mktemp -d)"
BACKUP_FILE="$TMP_DIR/pdns.sql"

export PDNS_POSTGRES_DB=pdns
export PDNS_POSTGRES_USER=pdns
export PDNS_POSTGRES_PASSWORD=acceptance-only-password
export PDNS_AUTH_API_KEY=acceptance-only-api-key
export PDNS_AUTH_WEBSERVER_PASSWORD=acceptance-only-web-password
export PDNS_POSTGRES_DATA="$TMP_DIR/postgres"
export PDNS_GPGSQL_DNS_PORT="${PDNS_GPGSQL_DNS_PORT:-15301}"
export PDNS_GPGSQL_API_PORT="${PDNS_GPGSQL_API_PORT:-18085}"
export COMPOSE_PROFILES=acceptance

cd "$ROOT"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon is not available"
  exit 0
fi

cleanup() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" config --quiet

if [[ "${ANYNS_RUN_DOCKER_GPGSQL_INTEGRATION:-1}" != "1" ]]; then
  echo "PowerDNS gpgsql compose config passed; runtime execution disabled"
  exit 0
fi

mkdir -p "$PDNS_POSTGRES_DATA"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" pull --policy always \
  pdns-postgres \
  pdns-authoritative \
  pdns-authoritative-init
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" build --pull dns-tools
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --wait

query_www() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T dns-tools \
    dig +short +time=2 +tries=1 @pdns-authoritative -p 5300 www.anyns.test A
}

test "$(query_www)" = "192.0.2.53"

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T pdns-postgres \
  pg_dump --clean --if-exists \
  --username="$PDNS_POSTGRES_USER" \
  --dbname="$PDNS_POSTGRES_DB" >"$BACKUP_FILE"
test -s "$BACKUP_FILE"

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T pdns-postgres \
  psql --username="$PDNS_POSTGRES_USER" --dbname="$PDNS_POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 \
  --command="UPDATE records SET content = '192.0.2.99' WHERE name = 'www.anyns.test' AND type = 'A';"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T pdns-authoritative \
  pdns_control purge www.anyns.test
test "$(query_www)" = "192.0.2.99"

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" stop pdns-authoritative
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T pdns-postgres \
  psql --username="$PDNS_POSTGRES_USER" --dbname="$PDNS_POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 <"$BACKUP_FILE"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" start pdns-authoritative

for _ in $(seq 1 30); do
  if [[ "$(query_www 2>/dev/null || true)" == "192.0.2.53" ]]; then
    echo "PowerDNS gpgsql initialization and backup/restore passed"
    exit 0
  fi
  sleep 1
done

echo "FAIL: restored PowerDNS answer did not become available"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" logs --no-color
exit 1
