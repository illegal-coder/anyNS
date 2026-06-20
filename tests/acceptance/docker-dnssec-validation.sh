#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT="${ANYNS_DNSSEC_PROJECT:-anyns-dnssec-validation}"
COMPOSE=(
  docker compose
  --project-name "$PROJECT"
  --file "$ROOT/tests/docker/compose.dns-integration.yml"
  --file "$ROOT/tests/docker/compose.dnssec.yml"
)

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    "${COMPOSE[@]}" ps || true
    "${COMPOSE[@]}" logs --no-color --tail=120 pdns-recursor pdns-authoritative anyns-admin-api dns-tools || true
  fi
  "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker is not available"
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 is not installed"
  exit 0
fi

cleanup
"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" build --pull anyns-plugin-runtime pdns-recursor dns-tools
"${COMPOSE[@]}" up -d --no-build \
  backend-fixtures \
  pdns-authoritative \
  pdns-recursor \
  anyns-plugin-runtime \
  anyns-admin-api \
  dns-tools

tools() {
  "${COMPOSE[@]}" exec -T dns-tools sh -euc "$*"
}

for _ in $(seq 1 60); do
  if tools '
    curl -fsS http://anyns-admin-api:8080/healthz >/dev/null
    dig +time=1 +tries=1 @pdns-authoritative -p 5300 version.bind TXT CH >/dev/null
    dig +time=1 +tries=1 @pdns-recursor version.bind TXT CH >/dev/null
  ' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

tools '
  curl -fsS http://anyns-admin-api:8080/healthz >/dev/null
  dig +time=1 +tries=1 @pdns-authoritative -p 5300 version.bind TXT CH >/dev/null
  dig +time=1 +tries=1 @pdns-recursor version.bind TXT CH >/dev/null
'

create_zone() {
  local label="$1"
  local glue_ipv4="$2"
  tools '
    curl -fsS \
      -X POST http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones \
      -H "Content-Type: application/json" \
      --data "{
        \"name\":\"'"$label"'.hns\",
        \"kind\":\"Native\",
        \"hns\":true,
        \"glue_ipv4\":\"'"$glue_ipv4"'\",
        \"soa\":{\"serial\":2026062001,\"ttl\":60,\"refresh\":300,\"retry\":60,\"expire\":3600,\"minimum\":60}
      }" |
      tee /tmp/'"$label"'-zone.json
    grep -q "\"name\":\"'"$label"'.\"" /tmp/'"$label"'-zone.json

    curl -fsS \
      -X PATCH http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones/'"$label"'./rrsets \
      -H "Content-Type: application/json" \
      --data "{
        \"rrsets\":[{
          \"name\":\"www.'"$label"'.\",
          \"type\":\"A\",
          \"ttl\":60,
          \"changetype\":\"REPLACE\",
          \"records\":[{\"content\":\"'"$glue_ipv4"'\",\"disabled\":false}]
        }]
      }"

    curl -fsS \
      -X POST http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones/'"$label"'./cryptokeys \
      -H "Content-Type: application/json" \
      --data "{\"keytype\":\"csk\",\"active\":true,\"published\":true}" |
      tee /tmp/'"$label"'-key.json
    grep -q "\"dnskey\"" /tmp/'"$label"'-key.json
  '
}

extract_ds() {
  local label="$1"
  tools '
    curl -fsS http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones/'"$label"'./cryptokeys >/tmp/'"$label"'-keys.json
    grep -Eo "\"[0-9]+ 13 2 [0-9a-fA-F]+\"" /tmp/'"$label"'-keys.json |
      head -1 |
      tr -d "\""
  ' | tail -1
}

corrupt_ds() {
  python3 - "$1" <<'PY'
import sys

parts = sys.argv[1].split()
digest = parts[3]
replacement = "0" if digest[-1].lower() != "0" else "1"
parts[3] = digest[:-1] + replacement
print(" ".join(parts))
PY
}

create_zone secure 192.0.2.60
create_zone bogus 192.0.2.61

SECURE_DS="$(extract_ds secure)"
BOGUS_DS="$(extract_ds bogus)"
CORRUPT_BOGUS_DS="$(corrupt_ds "$BOGUS_DS")"

"${COMPOSE[@]}" exec -T pdns-recursor rec_control add-ta secure "$SECURE_DS"
"${COMPOSE[@]}" exec -T pdns-recursor rec_control add-ta bogus "$CORRUPT_BOGUS_DS"
"${COMPOSE[@]}" exec -T pdns-recursor rec_control get-tas | tee /tmp/anyns-dnssec-tas.txt
grep -qx 'secure' /tmp/anyns-dnssec-tas.txt
grep -qx 'bogus' /tmp/anyns-dnssec-tas.txt

tools '
  dig +dnssec +adflag +time=2 +tries=1 @pdns-recursor www.secure. A |
    tee /tmp/secure-validation.txt
  grep -q "status: NOERROR" /tmp/secure-validation.txt
  grep -Eq "flags:.* ad[; ]" /tmp/secure-validation.txt
  grep -Eq "www\\.secure\\..*IN[[:space:]]+A[[:space:]]+192\\.0\\.2\\.60" /tmp/secure-validation.txt
  grep -Eq "www\\.secure\\..*IN[[:space:]]+RRSIG[[:space:]]+A" /tmp/secure-validation.txt

  dig +dnssec +adflag +time=2 +tries=1 @pdns-recursor www.bogus. A |
    tee /tmp/bogus-validation.txt
  grep -q "status: SERVFAIL" /tmp/bogus-validation.txt
  ! grep -Eq "flags:.* ad[; ]" /tmp/bogus-validation.txt
'

echo "DNSSEC validation Docker acceptance passed: secure AD chain and bogus SERVFAIL chain"
