#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/docker-compose.gpgsql.yml"
PROJECT="${ANYNS_GPGSQL_ROLLBACK_PROJECT:-anyns-gpgsql-rollback}"
TMP_DIR="$(mktemp -d)"
BACKUP_FILE="$TMP_DIR/pre-upgrade-pdns.sql"
IMAGES_BEFORE="$TMP_DIR/images-before.txt"

export PDNS_POSTGRES_DB=pdns
export PDNS_POSTGRES_USER=pdns
export PDNS_POSTGRES_PASSWORD=rollback-only-password
export PDNS_AUTH_API_KEY=rollback-only-api-key
export PDNS_AUTH_WEBSERVER_PASSWORD=rollback-only-web-password
export PDNS_POSTGRES_DATA="$TMP_DIR/postgres"
export PDNS_GPGSQL_DNS_PORT="${PDNS_GPGSQL_ROLLBACK_DNS_PORT:-15311}"
export PDNS_GPGSQL_API_PORT="${PDNS_GPGSQL_ROLLBACK_API_PORT:-18086}"
export COMPOSE_PROFILES=acceptance
export NO_PROXY="${NO_PROXY:+${NO_PROXY},}127.0.0.1,localhost"
export no_proxy="${no_proxy:+${no_proxy},}127.0.0.1,localhost"

cd "$ROOT"

for command in docker curl grep; do
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

cleanup() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" config --quiet

if [[ "${ANYNS_RUN_DOCKER_GPGSQL_ROLLBACK:-1}" != "1" ]]; then
  echo "PowerDNS gpgsql rollback compose config passed; runtime execution disabled"
  exit 0
fi

mkdir -p "$PDNS_POSTGRES_DATA"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" config --images >"$IMAGES_BEFORE"
grep -q 'postgres:17.5-alpine3.22@sha256:' "$IMAGES_BEFORE"
grep -q 'powerdns/pdns-auth-50:5.0.5@sha256:' "$IMAGES_BEFORE"
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

assert_api_zone() {
  curl -fsS \
    -H "X-API-Key: $PDNS_AUTH_API_KEY" \
    "http://127.0.0.1:$PDNS_GPGSQL_API_PORT/api/v1/servers/localhost/zones/anyns.test." \
    | grep -q '"name"[[:space:]]*:[[:space:]]*"anyns.test."'
}

echo "phase:baseline-health"
test "$(query_www)" = "192.0.2.53"
assert_api_zone

echo "phase:pre-upgrade-backup"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T pdns-postgres \
  pg_dump --clean --if-exists \
  --username="$PDNS_POSTGRES_USER" \
  --dbname="$PDNS_POSTGRES_DB" >"$BACKUP_FILE"
test -s "$BACKUP_FILE"

echo "phase:simulate-bad-upgrade"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T pdns-postgres \
  psql --username="$PDNS_POSTGRES_USER" --dbname="$PDNS_POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 \
  --command="UPDATE records SET content = '192.0.2.200' WHERE name = 'www.anyns.test' AND type = 'A';"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T pdns-authoritative \
  pdns_control purge www.anyns.test
test "$(query_www)" = "192.0.2.200"

echo "phase:rollback"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" stop pdns-authoritative
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T pdns-postgres \
  psql --username="$PDNS_POSTGRES_USER" --dbname="$PDNS_POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 <"$BACKUP_FILE"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" start pdns-authoritative

for _ in $(seq 1 30); do
  if [[ "$(query_www 2>/dev/null || true)" == "192.0.2.53" ]] && assert_api_zone; then
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" ps
    echo "PowerDNS gpgsql upgrade rollback passed"
    exit 0
  fi
  sleep 1
done

echo "FAIL: rollback did not restore PowerDNS health and answer"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" logs --no-color
exit 1
