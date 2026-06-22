#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT="${ANYNS_HNS_PRIVATE_CA_DEMO_PROJECT:-anyns-hns-private-ca-demo}"
COMPOSE=(
  docker compose
  --project-name "$PROJECT"
  --file "$ROOT/tests/docker/compose.dns-integration.yml"
  --file "$ROOT/tests/docker/compose.soa-tld.yml"
  --file "$ROOT/tests/docker/compose.hns-private-ca-demo.yml"
)
export COMPOSE_PARALLEL_LIMIT=1

cd "$ROOT"

for command in docker curl python3 openssl grep awk; do
  command -v "$command" >/dev/null || {
    echo "SKIP: $command is not installed"
    exit 0
  }
done
docker info >/dev/null
docker compose version >/dev/null

cleanup() {
  if [[ "${ANYNS_KEEP_HNS_PRIVATE_CA_DEMO:-}" != "1" ]]; then
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

cleanup
"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" build --pull bind-certgen anyns-plugin-runtime pdns-recursor dns-tools
"${COMPOSE[@]}" up -d --no-build \
  backend-fixtures \
  pdns-authoritative \
  pdns-recursor \
  anyns-plugin-runtime \
  anyns-admin-api \
  hns-private-ca-origin \
  bind-latest \
  dns-tools

tools() {
  "${COMPOSE[@]}" exec -T dns-tools sh -euc "$*"
}

container_json_value() {
  local file="$1"
  local key="$2"
  "${COMPOSE[@]}" exec -T dns-tools cat "$file" |
    python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$key"
}

wait_ready() {
  for _ in $(seq 1 60); do
    if tools '
      curl -fsS http://anyns-admin-api:8080/healthz >/dev/null
      dig +time=1 +tries=1 @pdns-authoritative -p 5300 version.bind TXT CH >/dev/null
      dig +time=1 +tries=1 @pdns-recursor version.bind TXT CH >/dev/null
      dig +time=1 +tries=1 @bind-latest version.bind TXT CH >/dev/null
    ' >/dev/null 2>&1; then
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
    tools 'curl -fsS http://anyns-admin-api:8080/api/v1/certificates/orders/'"$job_id"' >/tmp/hns-demo-job.json'
    status="$(container_json_value /tmp/hns-demo-job.json status)"
    if [[ "$status" == "$wanted" ]]; then
      return 0
    fi
    if [[ "$status" == "failed" && "$wanted" != "failed" ]]; then
      "${COMPOSE[@]}" exec -T dns-tools cat /tmp/hns-demo-job.json
      return 1
    fi
    sleep 1
  done
  "${COMPOSE[@]}" exec -T dns-tools cat /tmp/hns-demo-job.json
  return 1
}

wait_ready
tools 'curl -fsS http://anyns-admin-api:8080/ | grep -q "<div id=\"root\"></div>"'

echo "phase:create-hns-zone"
tools '
  curl -fsS \
    -X POST http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones \
    -H "Content-Type: application/json" \
    --data "{
      \"name\":\"example.hns\",
      \"kind\":\"Native\",
      \"hns\":true,
      \"glue_ipv4\":\"192.0.2.53\",
      \"glue_ipv6\":\"2001:db8::53\",
      \"soa\":{\"serial\":2026062201,\"ttl\":300,\"refresh\":7200,\"retry\":900,\"expire\":172800,\"minimum\":300}
    }" |
    tee /tmp/hns-demo-zone.json
  grep -q "\"name\":\"example.\"" /tmp/hns-demo-zone.json
  ! grep -q "\"name\":\"example.hns.\"" /tmp/hns-demo-zone.json

  dig +short @pdns-authoritative -p 5300 example. SOA |
    tee /tmp/hns-demo-soa.txt
  grep -Eq "^ns1\\.example\\. hostmaster\\.example\\. [0-9]+ 7200 900 172800 300$" /tmp/hns-demo-soa.txt
  dig +short @pdns-authoritative -p 5300 example. NS | grep -qx "ns1.example."
  dig +short @pdns-authoritative -p 5300 ns1.example. A | grep -qx "192.0.2.53"
  dig +short @pdns-authoritative -p 5300 ns1.example. AAAA | grep -qx "2001:db8::53"
'

echo "phase:dnssec-operator-data"
tools '
  curl -fsS -X POST http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones/example./cryptokeys \
    -H "Content-Type: application/json" \
    --data "{\"keytype\":\"csk\",\"active\":true,\"published\":true}" |
    tee /tmp/hns-demo-key.json
  grep -q "\"dnskey\"" /tmp/hns-demo-key.json
  grep -q "\"ds\"" /tmp/hns-demo-key.json
'

DNSKEY="$(container_json_value /tmp/hns-demo-key.json dnskey)"
tools "printf '%s' '$DNSKEY' >/tmp/hns-demo-dnskey.txt"
tools '
  dnskey=$(cat /tmp/hns-demo-dnskey.txt)
  curl -fsS -X POST http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones/example./derive-ds \
    -H "Content-Type: application/json" \
    --data "{\"dnskey\":\"$dnskey\",\"digest_type\":2}" |
    tee /tmp/hns-demo-derived-ds.json
  grep -q "\"zone\":\"example.\"" /tmp/hns-demo-derived-ds.json
  grep -q "\"ds\"" /tmp/hns-demo-derived-ds.json

  dig +dnssec +time=2 +tries=1 @pdns-authoritative -p 5300 example. DNSKEY |
    tee /tmp/hns-demo-dnskey-answer.txt
  grep -Eq "IN[[:space:]]+DNSKEY" /tmp/hns-demo-dnskey-answer.txt
  grep -Eq "IN[[:space:]]+RRSIG[[:space:]]+DNSKEY" /tmp/hns-demo-dnskey-answer.txt
'

echo "phase:private-ca-certificate"
tools '
  curl -fsS -X POST http://anyns-admin-api:8080/api/v1/certificates/orders \
    -H "Content-Type: application/json" \
    --data "{\"domains\":[\"www.example\",\"example\"],\"idempotency_key\":\"hns-demo-private-ca-1\"}" \
    >/tmp/hns-demo-order.json
'
JOB_ID="$(container_json_value /tmp/hns-demo-order.json id)"
poll_job "$JOB_ID" issued

tools '
  curl -fsS http://anyns-admin-api:8080/api/v1/certificates/orders/'"$JOB_ID"'/certificate >/tmp/hns-demo-chain.pem
  if grep -q -- "-----BEGIN PRIVATE KEY-----" /tmp/hns-demo-chain.pem; then
    echo "certificate chain exposed private key material"
    exit 1
  fi
  awk '"'"'
    /-----BEGIN CERTIFICATE-----/ { n++ }
    n == 1 { print > "/tmp/hns-demo-leaf.pem" }
    n == 2 { print > "/tmp/hns-demo-root-from-chain.pem" }
  '"'"' /tmp/hns-demo-chain.pem
  openssl x509 -in /tmp/hns-demo-leaf.pem -noout -ext subjectAltName | grep -q "DNS:www.example"
  openssl x509 -in /tmp/hns-demo-leaf.pem -noout -ext basicConstraints | grep -q "CA:FALSE"
  openssl x509 -in /tmp/hns-demo-leaf.pem -noout -ext extendedKeyUsage | grep -q "TLS Web Server Authentication"
  openssl x509 -in /tmp/hns-demo-leaf.pem -noout -text | grep -q "URI:http://anyns-admin-api:8080/private-ca.crl"
  openssl verify -CAfile /tmp/hns-demo-root-from-chain.pem /tmp/hns-demo-leaf.pem

  curl -fsS http://anyns-admin-api:8080/api/v1/certificates/private-ca/root/certificate >/tmp/hns-demo-root-download.pem
  cmp /tmp/hns-demo-root-from-chain.pem /tmp/hns-demo-root-download.pem
  if grep -q -- "-----BEGIN PRIVATE KEY-----" /tmp/hns-demo-root-download.pem; then
    echo "root certificate endpoint exposed private key material"
    exit 1
  fi
'

echo "phase:ocsp-good"
tools '
  curl -fsS http://anyns-admin-api:8080/api/v1/certificates/orders/'"$JOB_ID"'/ocsp >/tmp/hns-demo-ocsp-good.der
  openssl ocsp -sha256 -respin /tmp/hns-demo-ocsp-good.der \
    -issuer /tmp/hns-demo-root-from-chain.pem \
    -cert /tmp/hns-demo-leaf.pem \
    -noverify -text > /tmp/hns-demo-ocsp-good.txt
  grep -q "/tmp/hns-demo-leaf.pem: good" /tmp/hns-demo-ocsp-good.txt
  if grep -a -q -- "-----BEGIN PRIVATE ""KEY-----" /tmp/hns-demo-ocsp-good.der ||
     grep -a -q -- "-----BEGIN ""CERTIFICATE-----" /tmp/hns-demo-ocsp-good.der; then
    echo "OCSP endpoint exposed PEM material"
    exit 1
  fi
'

echo "phase:https-demo"
"${COMPOSE[@]}" exec -T hns-private-ca-origin sh -euc '
  test "$(stat -c %a /var/lib/anyns/certificates/certs/'"$JOB_ID"'/private-key.pem)" = "600"
  test "$(stat -c %a /var/lib/anyns/certificates/certs/'"$JOB_ID"'/fullchain.pem)" = "600"
'
tools '
  for _ in $(seq 1 20); do
    if NO_PROXY="*" no_proxy="*" curl -fsS \
      --cacert /tmp/hns-demo-root-download.pem \
      --connect-to www.example:8443:hns-private-ca-origin:8443 \
      https://www.example:8443/ >/tmp/hns-demo-https.txt; then
      break
    fi
    sleep 1
  done
  grep -q "s_server" /tmp/hns-demo-https.txt
  if NO_PROXY="*" no_proxy="*" curl -fsS \
    --connect-to www.example:8443:hns-private-ca-origin:8443 \
    https://www.example:8443/ >/tmp/hns-demo-untrusted.txt 2>&1; then
    echo "HTTPS demo accepted private root without explicit trust"
    exit 1
  fi
  if NO_PROXY="*" no_proxy="*" curl -fsS \
    --cacert /tmp/hns-demo-root-download.pem \
    --connect-to wrong.example:8443:hns-private-ca-origin:8443 \
    https://wrong.example:8443/ >/tmp/hns-demo-wrong-host.txt 2>&1; then
    echo "HTTPS demo accepted wrong hostname"
    exit 1
  fi
'

echo "phase:publish-tlsa"
tools '
  curl -fsS -X POST http://anyns-admin-api:8080/api/v1/certificates/tlsa \
    -H "Content-Type: application/json" \
    --data "{\"job_id\":\"'"$JOB_ID"'\",\"domain\":\"www.example\",\"port\":443,\"protocol\":\"tcp\",\"usage\":3,\"selector\":1,\"matching_type\":1,\"publish\":true,\"ttl\":300}" \
    >/tmp/hns-demo-tlsa.json
  grep -q "\"published\":true" /tmp/hns-demo-tlsa.json
  grep -q "\"owner\":\"_443._tcp.www.example.\"" /tmp/hns-demo-tlsa.json
  curl -fsS http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones/example. | grep -q "\"type\":\"TLSA\""
  dig +short @pdns-authoritative -p 5300 _443._tcp.www.example. TLSA |
    awk "{ for (i = 1; i <= NF; i++) fields[++n] = \$i } END { digest = \"\"; for (i = 4; i <= n; i++) digest = digest fields[i]; if (n >= 4) print fields[1], fields[2], fields[3], digest }" |
    tee /tmp/hns-demo-tlsa-answer.txt
  grep -Eq "^3 1 1 [0-9A-Fa-f]{64}$" /tmp/hns-demo-tlsa-answer.txt
'

echo "phase:revoke-and-crl"
tools '
  serial=$(openssl x509 -in /tmp/hns-demo-leaf.pem -noout -serial | cut -d= -f2 | sed "s/^0*//")
  curl -fsS -X POST http://anyns-admin-api:8080/api/v1/certificates/orders/'"$JOB_ID"'/revoke >/tmp/hns-demo-revoke.json
  grep -q "\"status\":\"revoked\"" /tmp/hns-demo-revoke.json
  curl -fsS http://anyns-admin-api:8080/api/v1/certificates/orders/'"$JOB_ID"'/ocsp >/tmp/hns-demo-ocsp-revoked.der
  openssl ocsp -sha256 -respin /tmp/hns-demo-ocsp-revoked.der \
    -issuer /tmp/hns-demo-root-from-chain.pem \
    -cert /tmp/hns-demo-leaf.pem \
    -noverify -text > /tmp/hns-demo-ocsp-revoked.txt
  grep -q "/tmp/hns-demo-leaf.pem: revoked" /tmp/hns-demo-ocsp-revoked.txt
  if grep -a -q -- "-----BEGIN PRIVATE ""KEY-----" /tmp/hns-demo-ocsp-revoked.der ||
     grep -a -q -- "-----BEGIN ""CERTIFICATE-----" /tmp/hns-demo-ocsp-revoked.der; then
    echo "revoked OCSP endpoint exposed PEM material"
    exit 1
  fi
  curl -fsS http://anyns-admin-api:8080/private-ca.crl >/tmp/hns-demo-public.crl
  openssl crl -in /tmp/hns-demo-public.crl -noout -text > /tmp/hns-demo-public-crl.txt
  serial_norm=$(printf "%s" "$serial" | tr -d " :" | tr "[:lower:]" "[:upper:]")
  crl_norm=$(tr -d " :\n" < /tmp/hns-demo-public-crl.txt | tr "[:lower:]" "[:upper:]")
  printf "%s" "$crl_norm" | grep -q "$serial_norm"
  if grep -q -- "-----BEGIN PRIVATE KEY-----" /tmp/hns-demo-public.crl; then
    echo "CRL endpoint exposed private key material"
    exit 1
  fi
'

echo "HNS private CA demo smoke passed: single-label TLD, SOA/NS/glue, DNSKEY/DS, private CA cert, HTTPS demo, root download, TLSA publish, OCSP, CRL reachability"
