#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/tests/docker/compose.private-ca.yml"
PROJECT="${ANYNS_PRIVATE_CA_PROJECT:-anyns-private-ca-certificates}"
export COMPOSE_PARALLEL_LIMIT=1
export NO_PROXY="${NO_PROXY:+${NO_PROXY},}127.0.0.1,localhost"
export no_proxy="${no_proxy:+${no_proxy},}127.0.0.1,localhost"

cd "$ROOT"

for command in docker curl python3 openssl awk grep; do
  command -v "$command" >/dev/null || {
    echo "SKIP: $command is not installed"
    exit 0
  }
done
docker info >/dev/null
docker compose version >/dev/null

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" config >/dev/null

cleanup() {
  if [[ "${ANYNS_KEEP_PRIVATE_CA_INTEGRATION:-}" != "1" ]]; then
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" build --pull --no-cache admin
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d admin

wait_healthz() {
  for _ in $(seq 1 45); do
    if curl -fsS http://127.0.0.1:28090/healthz >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

poll_job() {
  local job_id="$1"
  local wanted="$2"
  for _ in $(seq 1 45); do
    curl -fsS "http://127.0.0.1:28090/api/v1/certificates/orders/$job_id" >/tmp/anyns-private-ca-job.json
    status="$(python3 -c 'import json; print(json.load(open("/tmp/anyns-private-ca-job.json"))["status"])')"
    if [[ "$status" == "$wanted" ]]; then
      return 0
    fi
    if [[ "$status" == "failed" && "$wanted" != "failed" ]]; then
      cat /tmp/anyns-private-ca-job.json
      return 1
    fi
    sleep 1
  done
  cat /tmp/anyns-private-ca-job.json
  return 1
}

assert_job_status() {
  local job_id="$1"
  local wanted="$2"
  curl -fsS "http://127.0.0.1:28090/api/v1/certificates/orders/$job_id" >/tmp/anyns-private-ca-job.json
  python3 - "$wanted" <<'PY'
import json
import sys

wanted = sys.argv[1]
job = json.load(open("/tmp/anyns-private-ca-job.json"))
if job["status"] != wanted:
    raise SystemExit(f"job {job['id']} status {job['status']} != {wanted}")
if wanted == "issued" and (not job.get("not_before") or not job.get("not_after")):
    raise SystemExit("issued job is missing validity window")
if wanted == "revoked" and not job.get("revoked_at"):
    raise SystemExit("revoked job is missing revoked_at")
if "idempotency_key" in job:
    raise SystemExit("job response leaked idempotency_key")
PY
}

split_chain() {
  awk '
    /-----BEGIN CERTIFICATE-----/ { n++ }
    n == 1 { print > "/tmp/anyns-private-ca-leaf.pem" }
    n == 2 { print > "/tmp/anyns-private-ca-root.pem" }
  ' /tmp/anyns-private-ca-cert.pem
}

wait_healthz
curl -fsS http://127.0.0.1:28090/ | grep -q '<div id="root"></div>'

echo "phase:issue-private-ca-certificate"
curl -fsS -X POST http://127.0.0.1:28090/api/v1/certificates/orders \
  -H 'Content-Type: application/json' \
  --data '{"domains":["www.privateca.hns","privateca"],"idempotency_key":"private-ca-success-1"}' \
  >/tmp/anyns-private-ca-order.json
SUCCESS_ID="$(python3 -c 'import json; print(json.load(open("/tmp/anyns-private-ca-order.json"))["id"])')"
poll_job "$SUCCESS_ID" issued

curl -fsS "http://127.0.0.1:28090/api/v1/certificates/orders/$SUCCESS_ID/certificate" >/tmp/anyns-private-ca-cert.pem
if grep -q -- '-----BEGIN PRIVATE KEY-----' /tmp/anyns-private-ca-cert.pem; then
  echo "certificate download exposed private key material"
  exit 1
fi
split_chain
openssl x509 -in /tmp/anyns-private-ca-leaf.pem -noout -subject -issuer -dates
openssl x509 -in /tmp/anyns-private-ca-leaf.pem -noout -ext subjectAltName | grep -q 'DNS:www.privateca.hns'
openssl x509 -in /tmp/anyns-private-ca-leaf.pem -noout -ext subjectAltName | grep -q 'DNS:privateca'
openssl x509 -in /tmp/anyns-private-ca-leaf.pem -noout -ext basicConstraints | grep -q 'CA:FALSE'
openssl x509 -in /tmp/anyns-private-ca-leaf.pem -noout -ext extendedKeyUsage | grep -q 'TLS Web Server Authentication'
openssl x509 -in /tmp/anyns-private-ca-root.pem -noout -ext basicConstraints | grep -q 'CA:TRUE'
openssl verify -CAfile /tmp/anyns-private-ca-root.pem /tmp/anyns-private-ca-leaf.pem
openssl x509 -in /tmp/anyns-private-ca-leaf.pem -noout -fingerprint -sha256 >/tmp/anyns-private-ca-fingerprint-before.txt

echo "phase:inventory-and-tlsa"
curl -fsS http://127.0.0.1:28090/api/v1/certificates/orders >/tmp/anyns-private-ca-orders.json
python3 - "$SUCCESS_ID" <<'PY'
import json
import sys

job_id = sys.argv[1]
jobs = json.load(open("/tmp/anyns-private-ca-orders.json"))
matches = [job for job in jobs if job["id"] == job_id]
if len(matches) != 1:
    raise SystemExit(f"expected one inventory match for {job_id}, got {len(matches)}")
job = matches[0]
if job["status"] != "issued" or not job.get("not_before") or not job.get("not_after"):
    raise SystemExit(f"unexpected issued inventory job: {job}")
if "idempotency_key" in job:
    raise SystemExit("inventory leaked idempotency_key")
PY
curl -fsS -X POST http://127.0.0.1:28090/api/v1/certificates/tlsa \
  -H 'Content-Type: application/json' \
  --data "{\"job_id\":\"$SUCCESS_ID\",\"domain\":\"www.privateca.hns\",\"port\":443,\"protocol\":\"tcp\",\"usage\":3,\"selector\":1,\"matching_type\":1,\"publish\":false}" \
  >/tmp/anyns-private-ca-tlsa.json
python3 <<'PY'
import json
import re

response = json.load(open("/tmp/anyns-private-ca-tlsa.json"))
if response.get("owner") != "_443._tcp.www.privateca.hns.":
    raise SystemExit(f"unexpected TLSA owner: {response}")
if response.get("type") != "TLSA" or response.get("published") is not False:
    raise SystemExit(f"unexpected TLSA response: {response}")
parts = response.get("value", "").split()
if len(parts) != 4 or parts[:3] != ["3", "1", "1"] or not re.fullmatch(r"[0-9A-F]{64}", parts[3]):
    raise SystemExit(f"unexpected TLSA value: {response}")
PY

echo "phase:renew-private-ca-certificate"
curl -fsS -X POST "http://127.0.0.1:28090/api/v1/certificates/orders/$SUCCESS_ID/renew" \
  -H 'Content-Type: application/json' \
  --data '{"idempotency_key":"private-ca-renew-1","force":true}' \
  >/tmp/anyns-private-ca-renew.json
RENEW_ID="$(python3 - "$SUCCESS_ID" <<'PY'
import json
import sys

original = sys.argv[1]
job = json.load(open("/tmp/anyns-private-ca-renew.json"))
if job.get("renewal_of") != original:
    raise SystemExit(f"renewal response missing renewal_of: {job}")
print(job["id"])
PY
)"
poll_job "$RENEW_ID" issued
assert_job_status "$RENEW_ID" issued
curl -fsS "http://127.0.0.1:28090/api/v1/certificates/orders/$RENEW_ID/certificate" >/tmp/anyns-private-ca-cert.pem
if grep -q -- '-----BEGIN PRIVATE KEY-----' /tmp/anyns-private-ca-cert.pem; then
  echo "renewed certificate download exposed private key material"
  exit 1
fi
split_chain
openssl verify -CAfile /tmp/anyns-private-ca-root.pem /tmp/anyns-private-ca-leaf.pem
openssl x509 -in /tmp/anyns-private-ca-leaf.pem -noout -fingerprint -sha256 >/tmp/anyns-private-ca-fingerprint-renewed.txt
if cmp -s /tmp/anyns-private-ca-fingerprint-before.txt /tmp/anyns-private-ca-fingerprint-renewed.txt; then
  echo "renewed private CA certificate reused the original certificate fingerprint"
  exit 1
fi

echo "phase:revoke-private-ca-certificate"
curl -fsS -X POST "http://127.0.0.1:28090/api/v1/certificates/orders/$SUCCESS_ID/revoke" >/tmp/anyns-private-ca-revoke.json
grep -q '"status":"revoked"' /tmp/anyns-private-ca-revoke.json
assert_job_status "$SUCCESS_ID" revoked
curl -fsS "http://127.0.0.1:28090/api/v1/certificates/orders/$SUCCESS_ID/certificate" >/tmp/anyns-private-ca-cert.pem
if grep -q -- '-----BEGIN PRIVATE KEY-----' /tmp/anyns-private-ca-cert.pem; then
  echo "revoked certificate download exposed private key material"
  exit 1
fi
renew_status="$(curl -sS -o /tmp/anyns-private-ca-renew-revoked.json -w "%{http_code}" -X POST "http://127.0.0.1:28090/api/v1/certificates/orders/$SUCCESS_ID/renew" \
  -H 'Content-Type: application/json' \
  --data '{"idempotency_key":"private-ca-renew-revoked","force":true}')"
test "$renew_status" = "400"
curl -fsS http://127.0.0.1:28090/api/v1/certificates/orders >/tmp/anyns-private-ca-orders.json
python3 - "$SUCCESS_ID" "$RENEW_ID" <<'PY'
import json
import sys

original, renewed = sys.argv[1:3]
jobs = {job["id"]: job for job in json.load(open("/tmp/anyns-private-ca-orders.json"))}
if jobs[original]["status"] != "revoked" or not jobs[original].get("revoked_at"):
    raise SystemExit(f"original job not revoked in inventory: {jobs[original]}")
if jobs[renewed]["status"] != "issued" or jobs[renewed].get("renewal_of") != original:
    raise SystemExit(f"renewed job missing issued renewal linkage: {jobs[renewed]}")
if any("idempotency_key" in job for job in jobs.values()):
    raise SystemExit("inventory leaked idempotency_key")
PY

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T admin sh -lc \
  'test "$(stat -c %a /var/lib/anyns/certificates/private-ca/root-key.pem)" = "600"; \
   test "$(stat -c %a /var/lib/anyns/certificates/private-ca/root-cert.pem)" = "644"; \
   test "$(stat -c %a /var/lib/anyns/certificates/certs/'"$SUCCESS_ID"'/private-key.pem)" = "600"; \
   test "$(stat -c %a /var/lib/anyns/certificates/certs/'"$RENEW_ID"'/private-key.pem)" = "600"; \
   test -s /var/lib/anyns/certificates/state.json'

echo "phase:restart-persistence"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" restart admin
wait_healthz
assert_job_status "$SUCCESS_ID" revoked
assert_job_status "$RENEW_ID" issued

echo "phase:backup-restore"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T admin sh -lc \
  'rm -f /tmp/anyns-private-ca-backup.tgz; \
   tar -C /var/lib/anyns -czf /tmp/anyns-private-ca-backup.tgz certificates; \
   rm -rf /var/lib/anyns/certificates; \
   mkdir -p /var/lib/anyns; \
   tar -C /var/lib/anyns -xzf /tmp/anyns-private-ca-backup.tgz; \
   test "$(stat -c %a /var/lib/anyns/certificates/private-ca/root-key.pem)" = "600"; \
   test "$(stat -c %a /var/lib/anyns/certificates/certs/'"$SUCCESS_ID"'/private-key.pem)" = "600"; \
   test "$(stat -c %a /var/lib/anyns/certificates/certs/'"$RENEW_ID"'/private-key.pem)" = "600"; \
   rm -f /tmp/anyns-private-ca-backup.tgz'
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" restart admin
wait_healthz
assert_job_status "$SUCCESS_ID" revoked
assert_job_status "$RENEW_ID" issued
curl -fsS "http://127.0.0.1:28090/api/v1/certificates/orders/$RENEW_ID/certificate" >/tmp/anyns-private-ca-cert.pem
split_chain
openssl verify -CAfile /tmp/anyns-private-ca-root.pem /tmp/anyns-private-ca-leaf.pem
openssl x509 -in /tmp/anyns-private-ca-leaf.pem -noout -fingerprint -sha256 >/tmp/anyns-private-ca-fingerprint-after.txt
cmp /tmp/anyns-private-ca-fingerprint-renewed.txt /tmp/anyns-private-ca-fingerprint-after.txt

echo "private CA certificate integration passed"
