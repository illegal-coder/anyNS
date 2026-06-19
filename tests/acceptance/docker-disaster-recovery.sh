#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GPGSQL_COMPOSE="$ROOT/docker-compose.gpgsql.yml"
PRIVATE_CA_COMPOSE="$ROOT/tests/docker/compose.private-ca.yml"
SOURCE_PROJECT="${ANYNS_DR_SOURCE_PROJECT:-anyns-dr-source}"
TARGET_PROJECT="${ANYNS_DR_TARGET_PROJECT:-anyns-dr-target}"
CERT_BACKUP_VOLUME="${ANYNS_DR_CERT_BACKUP_VOLUME:-anyns-dr-cert-backup}"
ALPINE_IMAGE="alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
TMP_DIR="$(mktemp -d)"
DNS_BACKUP_FILE="$TMP_DIR/pdns.sql"

export COMPOSE_PROFILES=acceptance
export ANYNS_ADMIN_BUILD_CONTEXT="$ROOT"
export ANYNS_PRIVATE_CA_CONFIG_PATH="$ROOT/tests/docker/anyns-private-ca-config.json"
export NO_PROXY="${NO_PROXY:+${NO_PROXY},}127.0.0.1,localhost"
export no_proxy="${no_proxy:+${no_proxy},}127.0.0.1,localhost"

cd "$ROOT"

for command in docker curl python3 openssl awk grep cmp; do
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
  source_compose down -v --remove-orphans >/dev/null 2>&1 || true
  target_compose down -v --remove-orphans >/dev/null 2>&1 || true
  docker volume rm "$CERT_BACKUP_VOLUME" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

source_env() {
  export PDNS_POSTGRES_DB=pdns
  export PDNS_POSTGRES_USER=pdns
  export PDNS_POSTGRES_PASSWORD=dr-source-password
  export PDNS_AUTH_API_KEY=dr-source-api-key
  export PDNS_AUTH_WEBSERVER_PASSWORD=dr-source-web-password
  export PDNS_POSTGRES_DATA="$TMP_DIR/source-postgres"
  export PDNS_GPGSQL_DNS_PORT="${ANYNS_DR_SOURCE_DNS_PORT:-15321}"
  export PDNS_GPGSQL_API_PORT="${ANYNS_DR_SOURCE_API_PORT:-18091}"
  export ANYNS_PRIVATE_CA_ADMIN_PORT="${ANYNS_DR_SOURCE_ADMIN_PORT:-28091}"
}

target_env() {
  export PDNS_POSTGRES_DB=pdns
  export PDNS_POSTGRES_USER=pdns
  export PDNS_POSTGRES_PASSWORD=dr-target-password
  export PDNS_AUTH_API_KEY=dr-target-api-key
  export PDNS_AUTH_WEBSERVER_PASSWORD=dr-target-web-password
  export PDNS_POSTGRES_DATA="$TMP_DIR/target-postgres"
  export PDNS_GPGSQL_DNS_PORT="${ANYNS_DR_TARGET_DNS_PORT:-15322}"
  export PDNS_GPGSQL_API_PORT="${ANYNS_DR_TARGET_API_PORT:-18092}"
  export ANYNS_PRIVATE_CA_ADMIN_PORT="${ANYNS_DR_TARGET_ADMIN_PORT:-28092}"
}

source_compose() {
  source_env
  docker compose -p "$SOURCE_PROJECT" -f "$GPGSQL_COMPOSE" -f "$PRIVATE_CA_COMPOSE" "$@"
}

target_compose() {
  target_env
  docker compose -p "$TARGET_PROJECT" -f "$GPGSQL_COMPOSE" -f "$PRIVATE_CA_COMPOSE" "$@"
}

wait_admin() {
  local port="$1"
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

poll_job() {
  local port="$1"
  local job_id="$2"
  for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:$port/api/v1/certificates/orders/$job_id" >/tmp/anyns-dr-job.json
    status="$(python3 -c 'import json; print(json.load(open("/tmp/anyns-dr-job.json"))["status"])')"
    if [[ "$status" == "issued" ]]; then
      return 0
    fi
    if [[ "$status" == "failed" ]]; then
      cat /tmp/anyns-dr-job.json
      return 1
    fi
    sleep 1
  done
  cat /tmp/anyns-dr-job.json
  return 1
}

query_www() {
  local project="$1"
  docker compose -p "$project" -f "$GPGSQL_COMPOSE" -f "$PRIVATE_CA_COMPOSE" exec -T dns-tools \
    dig +short +time=2 +tries=1 @pdns-authoritative -p 5300 www.anyns.test A
}

assert_api_zone() {
  local port="$1"
  local api_key="$2"
  curl -fsS \
    -H "X-API-Key: $api_key" \
    "http://127.0.0.1:$port/api/v1/servers/localhost/zones/anyns.test." \
    | grep -q '"name"[[:space:]]*:[[:space:]]*"anyns.test."'
}

split_chain() {
  awk '
    /-----BEGIN CERTIFICATE-----/ { n++ }
    n == 1 { print > "/tmp/anyns-dr-leaf.pem" }
    n == 2 { print > "/tmp/anyns-dr-root.pem" }
  ' /tmp/anyns-dr-cert.pem
}

source_compose config --quiet
target_compose config --quiet

if [[ "${ANYNS_RUN_DOCKER_DR:-1}" != "1" ]]; then
  echo "Disaster recovery compose config passed; runtime execution disabled"
  exit 0
fi

mkdir -p "$TMP_DIR/source-postgres" "$TMP_DIR/target-postgres"
source_compose pull --policy always pdns-postgres pdns-authoritative pdns-authoritative-init
source_compose build --pull dns-tools admin
source_compose up -d --wait
wait_admin "${ANYNS_DR_SOURCE_ADMIN_PORT:-28091}"

echo "phase:source-state"
test "$(query_www "$SOURCE_PROJECT")" = "192.0.2.53"
assert_api_zone "${ANYNS_DR_SOURCE_API_PORT:-18091}" "dr-source-api-key"
curl -fsS -X POST "http://127.0.0.1:${ANYNS_DR_SOURCE_ADMIN_PORT:-28091}/api/v1/certificates/orders" \
  -H 'Content-Type: application/json' \
  --data '{"domains":["www.dr-privateca.hns","dr-privateca"],"idempotency_key":"dr-cert-1"}' \
  >/tmp/anyns-dr-order.json
CERT_ID="$(python3 -c 'import json; print(json.load(open("/tmp/anyns-dr-order.json"))["id"])')"
poll_job "${ANYNS_DR_SOURCE_ADMIN_PORT:-28091}" "$CERT_ID"
curl -fsS "http://127.0.0.1:${ANYNS_DR_SOURCE_ADMIN_PORT:-28091}/api/v1/certificates/orders/$CERT_ID/certificate" >/tmp/anyns-dr-cert.pem
if grep -q -- '-----BEGIN PRIVATE KEY-----' /tmp/anyns-dr-cert.pem; then
  echo "source certificate download exposed private key material"
  exit 1
fi
split_chain
openssl verify -CAfile /tmp/anyns-dr-root.pem /tmp/anyns-dr-leaf.pem
openssl x509 -in /tmp/anyns-dr-leaf.pem -noout -fingerprint -sha256 >/tmp/anyns-dr-source-fingerprint.txt

echo "phase:backup"
source_env
source_compose exec -T pdns-postgres \
  pg_dump --clean --if-exists \
  --username="$PDNS_POSTGRES_USER" \
  --dbname="$PDNS_POSTGRES_DB" >"$DNS_BACKUP_FILE"
test -s "$DNS_BACKUP_FILE"
docker volume create "$CERT_BACKUP_VOLUME" >/dev/null
docker run --rm \
  -v "${SOURCE_PROJECT}_private-ca-admin-data:/src:ro" \
  -v "$CERT_BACKUP_VOLUME:/backup" \
  "$ALPINE_IMAGE" \
  sh -lc 'cd /src && tar -czf /backup/certificates.tgz certificates'

target_compose pull --policy always pdns-postgres pdns-authoritative pdns-authoritative-init
target_compose build --pull dns-tools admin
target_compose up -d --wait
wait_admin "${ANYNS_DR_TARGET_ADMIN_PORT:-28092}"

echo "phase:restore-target"
target_compose stop pdns-authoritative admin
target_compose exec -T pdns-postgres \
  psql --username="$PDNS_POSTGRES_USER" --dbname="$PDNS_POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 <"$DNS_BACKUP_FILE"
docker run --rm \
  -v "${TARGET_PROJECT}_private-ca-admin-data:/dst" \
  -v "$CERT_BACKUP_VOLUME:/backup:ro" \
  "$ALPINE_IMAGE" \
  sh -lc 'rm -rf /dst/certificates && tar -xzf /backup/certificates.tgz -C /dst'
target_compose start pdns-authoritative admin
wait_admin "${ANYNS_DR_TARGET_ADMIN_PORT:-28092}"

echo "phase:target-verify"
for _ in $(seq 1 60); do
  if [[ "$(query_www "$TARGET_PROJECT" 2>/dev/null || true)" == "192.0.2.53" ]] &&
     assert_api_zone "${ANYNS_DR_TARGET_API_PORT:-18092}" "dr-target-api-key"; then
    break
  fi
  sleep 1
done
test "$(query_www "$TARGET_PROJECT")" = "192.0.2.53"
assert_api_zone "${ANYNS_DR_TARGET_API_PORT:-18092}" "dr-target-api-key"
curl -fsS "http://127.0.0.1:${ANYNS_DR_TARGET_ADMIN_PORT:-28092}/api/v1/certificates/orders/$CERT_ID" \
  | grep -q '"status":"issued"'
curl -fsS "http://127.0.0.1:${ANYNS_DR_TARGET_ADMIN_PORT:-28092}/api/v1/certificates/orders/$CERT_ID/certificate" >/tmp/anyns-dr-cert.pem
if grep -q -- '-----BEGIN PRIVATE KEY-----' /tmp/anyns-dr-cert.pem; then
  echo "target certificate download exposed private key material"
  exit 1
fi
split_chain
openssl verify -CAfile /tmp/anyns-dr-root.pem /tmp/anyns-dr-leaf.pem
openssl x509 -in /tmp/anyns-dr-leaf.pem -noout -fingerprint -sha256 >/tmp/anyns-dr-target-fingerprint.txt
cmp /tmp/anyns-dr-source-fingerprint.txt /tmp/anyns-dr-target-fingerprint.txt

echo "Docker disaster recovery smoke passed"
