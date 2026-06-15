#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/tests/docker/compose.decentralized-certificates.yml"
PROJECT="${ANYNS_CERTIFICATE_PROJECT:-anyns-decentralized-certificates}"
export COMPOSE_PARALLEL_LIMIT=1

cd "$ROOT"

for command in docker curl python3 openssl; do
  command -v "$command" >/dev/null || {
    echo "SKIP: $command is not installed"
    exit 0
  }
done
docker info >/dev/null
docker compose version >/dev/null

echo "resource-baseline"
date -Is
uptime
free -h
df -h /
df -i /
docker ps --format '{{.Names}}|{{.Status}}|{{.Ports}}'
ps -eo pid,comm,%cpu,%mem,rss,etime,args --sort=-%cpu | grep -E 'codex|go test|go build|npm|node|docker build' | grep -v grep | head -20 || true

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" config >/dev/null

cleanup() {
  if [[ "${ANYNS_KEEP_CERTIFICATE_SIDELOAD:-}" != "1" ]]; then
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" pull pdns pebble
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" build --pull --no-cache admin
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d pdns
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d pebble
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d admin

for _ in $(seq 1 90); do
  if curl -fsS http://127.0.0.1:28080/healthz >/dev/null &&
     curl -fsS -H 'X-API-Key: side-load-only' http://127.0.0.1:28083/api/v1/servers/localhost >/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS http://127.0.0.1:28080/healthz >/dev/null
curl -fsS http://127.0.0.1:28080/ | grep -q '<div id="root"></div>'

echo "phase:create-zone-and-dnssec"
curl -fsS -X POST http://127.0.0.1:28080/api/v1/powerdns/authoritative/zones \
  -H 'Content-Type: application/json' \
  --data '{"name":"acme.anyns.test","kind":"Native","nameservers":["ns1.acme.anyns.test."],"glue_ipv4":"192.0.2.53","soa":{"primary_ns":"ns1.acme.anyns.test.","hostmaster":"hostmaster.acme.anyns.test.","ttl":60}}' \
  >/tmp/anyns-acme-zone.json

curl -fsS -X PATCH http://127.0.0.1:28080/api/v1/powerdns/authoritative/zones/acme.anyns.test./rrsets \
  -H 'Content-Type: application/json' \
  --data '{"rrsets":[
    {"name":"child.acme.anyns.test.","type":"DS","ttl":300,"changetype":"REPLACE","records":[{"content":"12345 13 2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]},
    {"name":"acme.anyns.test.","type":"CAA","ttl":300,"changetype":"REPLACE","records":[{"content":"0 issue \"pebble\""}]},
    {"name":"ns2.acme.anyns.test.","type":"NS","ttl":300,"changetype":"REPLACE","records":[{"content":"ns1.acme.anyns.test."}]}
  ]}' >/dev/null

curl -fsS -X POST http://127.0.0.1:28080/api/v1/powerdns/authoritative/zones/acme.anyns.test./cryptokeys \
  -H 'Content-Type: application/json' \
  --data '{"keytype":"csk","active":true,"published":true}' >/tmp/anyns-acme-key.json
grep -q '"dnskey"' /tmp/anyns-acme-key.json
curl -fsS http://127.0.0.1:28080/api/v1/powerdns/authoritative/zones/acme.anyns.test./cryptokeys | grep -q '"ds"'
curl -fsS http://127.0.0.1:28080/api/v1/powerdns/authoritative/zones | grep -q '"name":"acme.anyns.test."'
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T pdns \
  sdig 127.0.0.1 53 acme.anyns.test DNSKEY dnssec >/tmp/anyns-acme-dnskey.txt
grep -Eq 'IN[[:space:]]+DNSKEY' /tmp/anyns-acme-dnskey.txt
grep -Eq 'IN[[:space:]]+RRSIG[[:space:]]+DNSKEY' /tmp/anyns-acme-dnskey.txt
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T pdns \
  sdig 127.0.0.1 53 child.acme.anyns.test DS dnssec >/tmp/anyns-acme-ds.txt
grep -Eq 'IN[[:space:]]+DS' /tmp/anyns-acme-ds.txt
grep -Eq 'IN[[:space:]]+RRSIG[[:space:]]+DS' /tmp/anyns-acme-ds.txt

echo "phase:issue-certificate"
curl -fsS -X POST http://127.0.0.1:28080/api/v1/certificates/orders \
  -H 'Content-Type: application/json' \
  --data '{"domains":["www.acme.anyns.test"],"idempotency_key":"side-load-success-1"}' \
  >/tmp/anyns-acme-order.json
SUCCESS_ID="$(python3 -c 'import json; print(json.load(open("/tmp/anyns-acme-order.json"))["id"])')"

poll_job() {
  local job_id="$1"
  local wanted="$2"
  for _ in $(seq 1 90); do
    curl -fsS "http://127.0.0.1:28080/api/v1/certificates/orders/$job_id" >/tmp/anyns-acme-job.json
    status="$(python3 -c 'import json; print(json.load(open("/tmp/anyns-acme-job.json"))["status"])')"
    if [[ "$status" == "$wanted" ]]; then
      return 0
    fi
    if [[ "$status" == "failed" && "$wanted" != "failed" ]]; then
      cat /tmp/anyns-acme-job.json
      return 1
    fi
    sleep 1
  done
  cat /tmp/anyns-acme-job.json
  return 1
}

poll_job "$SUCCESS_ID" issued
curl -fsS "http://127.0.0.1:28080/api/v1/certificates/orders/$SUCCESS_ID/certificate" >/tmp/anyns-acme-cert.pem
openssl x509 -in /tmp/anyns-acme-cert.pem -noout -subject -issuer -dates
openssl x509 -in /tmp/anyns-acme-cert.pem -noout -ext subjectAltName | grep -q 'DNS:www.acme.anyns.test'
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T admin sh -lc \
  'test "$(stat -c %a /var/lib/anyns/certificates/account-key.pem)" = "600"; test "$(stat -c %a /var/lib/anyns/certificates/certs/'"$SUCCESS_ID"'/private-key.pem)" = "600"'
echo "phase:restart-persistence"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" restart admin
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:28080/healthz >/dev/null && break
  sleep 1
done
curl -fsS "http://127.0.0.1:28080/api/v1/certificates/orders/$SUCCESS_ID" | grep -q '"status":"issued"'

echo "phase:publish-tlsa"
curl -fsS -X POST http://127.0.0.1:28080/api/v1/certificates/tlsa \
  -H 'Content-Type: application/json' \
  --data "{\"job_id\":\"$SUCCESS_ID\",\"domain\":\"www.acme.anyns.test\",\"port\":443,\"protocol\":\"tcp\",\"usage\":3,\"selector\":1,\"matching_type\":1,\"publish\":true,\"ttl\":300}" \
  >/tmp/anyns-acme-tlsa.json
grep -q '"published":true' /tmp/anyns-acme-tlsa.json
curl -fsS http://127.0.0.1:28080/api/v1/powerdns/authoritative/zones/acme.anyns.test. | grep -q '"type":"TLSA"'

echo "phase:renew-certificate"
curl -fsS -X POST "http://127.0.0.1:28080/api/v1/certificates/orders/$SUCCESS_ID/renew" \
  -H 'Content-Type: application/json' \
  --data '{"idempotency_key":"side-load-renew-1","force":true}' >/tmp/anyns-acme-renew.json
RENEW_ID="$(python3 -c 'import json; print(json.load(open("/tmp/anyns-acme-renew.json"))["id"])')"
poll_job "$RENEW_ID" issued

echo "phase:revoke-certificate"
curl -fsS -X POST "http://127.0.0.1:28080/api/v1/certificates/orders/$SUCCESS_ID/revoke" >/tmp/anyns-acme-revoke.json
grep -q '"status":"revoked"' /tmp/anyns-acme-revoke.json

echo "phase:negative-issuance"
curl -fsS -X POST http://127.0.0.1:28080/api/v1/certificates/orders \
  -H 'Content-Type: application/json' \
  --data '{"domains":["missing.anyns.invalid"],"idempotency_key":"side-load-failure-1"}' \
  >/tmp/anyns-acme-failure.json
FAILURE_ID="$(python3 -c 'import json; print(json.load(open("/tmp/anyns-acme-failure.json"))["id"])')"
poll_job "$FAILURE_ID" failed

echo "resource-peak-snapshot"
docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.BlockIO}}'
uptime
free -h
df -h /
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" ps

echo "decentralized certificate side-load verification passed"
