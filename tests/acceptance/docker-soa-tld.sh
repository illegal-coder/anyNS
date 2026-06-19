#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT="${ANYNS_SOA_TLD_PROJECT:-anyns-soa-tld}"
COMPOSE=(
  docker compose
  --project-name "$PROJECT"
  --file "$ROOT/tests/docker/compose.dns-integration.yml"
  --file "$ROOT/tests/docker/compose.soa-tld.yml"
)

cleanup() {
  "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker is not available"
  exit 0
fi

cleanup
"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" build --pull bind-certgen anyns-plugin-runtime pdns-recursor dns-tools
"${COMPOSE[@]}" up -d --no-build \
  backend-fixtures \
  pdns-authoritative \
  pdns-recursor \
  anyns-plugin-runtime \
  anyns-admin-api \
  bind-latest \
  dns-tools

tools() {
  "${COMPOSE[@]}" exec -T dns-tools sh -euc "$*"
}

for _ in $(seq 1 60); do
  if tools '
    curl -fsS http://anyns-admin-api:8080/healthz >/dev/null
    dig +time=1 +tries=1 @pdns-authoritative -p 5300 version.bind TXT CH >/dev/null
    dig +time=1 +tries=1 @pdns-recursor version.bind TXT CH >/dev/null
    dig +time=1 +tries=1 @bind-latest version.bind TXT CH >/dev/null
  ' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

tools '
  curl -fsS http://anyns-admin-api:8080/healthz >/dev/null
  dig +time=1 +tries=1 @pdns-authoritative -p 5300 version.bind TXT CH >/dev/null
  dig +time=1 +tries=1 @pdns-recursor version.bind TXT CH >/dev/null
  dig +time=1 +tries=1 @bind-latest version.bind TXT CH >/dev/null
'

tools '
  status=$(curl -sS -o /tmp/invalid-child.json -w "%{http_code}" \
    -X POST http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones \
    -H "Content-Type: application/json" \
    --data "{\"name\":\"www.example\",\"kind\":\"Native\",\"hns\":true,\"glue_ipv4\":\"192.0.2.53\"}")
  test "$status" = "400"
  grep -q "single top-level label" /tmp/invalid-child.json
'

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
      \"soa\":{\"serial\":2026061901,\"ttl\":600,\"refresh\":7200,\"retry\":900,\"expire\":172800,\"minimum\":600}
    }" |
    tee /tmp/example-zone.json
  grep -q "\"name\":\"example.\"" /tmp/example-zone.json
  ! grep -q "\"name\":\"example.hns.\"" /tmp/example-zone.json
'

tools '
  curl -fsS \
    -X POST http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones \
    -H "Content-Type: application/json" \
    --data "{
      \"name\":\"灵.hns\",
      \"kind\":\"Native\",
      \"hns\":true,
      \"glue_ipv4\":\"192.0.2.54\",
      \"soa\":{\"serial\":2026061901}
    }" |
    tee /tmp/unicode-zone.json
  grep -q "\"name\":\"xn--5nx.\"" /tmp/unicode-zone.json
  grep -q "\"unicode_name\":\"灵.\"" /tmp/unicode-zone.json
'

tools '
  dig +time=2 +tries=1 +norecurse @pdns-authoritative -p 5300 example. SOA |
    tee /tmp/auth-example-soa.txt
  grep -Eq "flags:.* aa[; ]" /tmp/auth-example-soa.txt
  grep -Eq "example\\..*SOA.*ns1\\.example\\. hostmaster\\.example\\. [0-9]+ 7200 900 172800 600" /tmp/auth-example-soa.txt

  dig +short @pdns-authoritative -p 5300 example. NS |
    tee /tmp/auth-example-ns.txt
  grep -qx "ns1.example." /tmp/auth-example-ns.txt

  dig +short @pdns-authoritative -p 5300 ns1.example. A |
    tee /tmp/auth-example-a.txt
  grep -qx "192.0.2.53" /tmp/auth-example-a.txt

  dig +short @pdns-authoritative -p 5300 ns1.example. AAAA |
    tee /tmp/auth-example-aaaa.txt
  grep -qx "2001:db8::53" /tmp/auth-example-aaaa.txt

  dig +short @pdns-authoritative -p 5300 xn--5nx. SOA |
    tee /tmp/auth-unicode-soa.txt
  grep -Eq "^ns1\\.xn--5nx\\. hostmaster\\.xn--5nx\\. [0-9]+ " /tmp/auth-unicode-soa.txt
'

tools '
  authoritative_soa=$(dig +short @pdns-authoritative -p 5300 example. SOA)
  recursive_soa=$(dig +short @pdns-recursor example. SOA)
  printf "%s\n" "$recursive_soa" | tee /tmp/recursor-example-soa.txt
  test "$recursive_soa" = "$authoritative_soa"
  printf "%s\n" "$recursive_soa" |
    grep -Eq "^ns1\\.example\\. hostmaster\\.example\\. [0-9]+ 7200 900 172800 600$"

  dig +short @pdns-recursor example. NS |
    tee /tmp/recursor-example-ns.txt
  grep -qx "ns1.example." /tmp/recursor-example-ns.txt

  dig +short @pdns-recursor ns1.example. A |
    tee /tmp/recursor-example-a.txt
  grep -qx "192.0.2.53" /tmp/recursor-example-a.txt

  authoritative_unicode_soa=$(dig +short @pdns-authoritative -p 5300 xn--5nx. SOA)
  recursive_unicode_soa=$(dig +short @pdns-recursor xn--5nx. SOA)
  printf "%s\n" "$recursive_unicode_soa" | tee /tmp/recursor-unicode-soa.txt
  test "$recursive_unicode_soa" = "$authoritative_unicode_soa"
'

tools '
  initial_serial=$(dig +short @pdns-authoritative -p 5300 example. SOA | awk "{print \$3}")
  test "$initial_serial" -gt 0
  requested_serial=$((initial_serial + 1))

  curl -fsS \
    -X PATCH http://anyns-admin-api:8080/api/v1/powerdns/authoritative/zones/example./rrsets \
    -H "Content-Type: application/json" \
    --data "{
      \"rrsets\":[{
        \"name\":\"example.\",
        \"type\":\"SOA\",
        \"ttl\":600,
        \"changetype\":\"REPLACE\",
        \"records\":[{
          \"content\":\"ns1.example. hostmaster.example. $requested_serial 7200 900 172800 600\",
          \"disabled\":false
        }]
      }]
    }"

  dig +short @pdns-authoritative -p 5300 example. SOA |
    tee /tmp/auth-example-soa-updated.txt
  updated_serial=$(awk "{print \$3}" /tmp/auth-example-soa-updated.txt)
  test "$updated_serial" -gt "$initial_serial"
  printf "%s\n" "$updated_serial" >/tmp/updated-serial
'

"${COMPOSE[@]}" restart pdns-recursor >/dev/null
for _ in $(seq 1 30); do
  if tools 'dig +time=1 +tries=1 @pdns-recursor version.bind TXT CH >/dev/null' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

tools '
  updated_serial=$(cat /tmp/updated-serial)
  dig +short @pdns-recursor example. SOA |
    tee /tmp/recursor-example-soa-updated.txt
  recursive_serial=$(awk "{print \$3}" /tmp/recursor-example-soa-updated.txt)
  test "$recursive_serial" = "$updated_serial"
'

tools '
  updated_serial=$(cat /tmp/updated-serial)
  openssl verify -CAfile /certs/ca.crt /certs/server.crt

  dig +time=2 +tries=1 @bind-latest example. SOA |
    tee /tmp/bind-example-soa.txt
  grep -Eq "example\\..*SOA.*ns1\\.example\\. hostmaster\\.example\\. $updated_serial 7200 900 172800 600" /tmp/bind-example-soa.txt

  kdig -p 853 +tls-ca=/certs/ca.crt +tls-hostname=bind-latest @bind-latest example. SOA |
    tee /tmp/bind-dot-example-soa.txt
  grep -Eq "example\\..*[[:space:]]SOA[[:space:]]+ns1\\.example\\. hostmaster\\.example\\. $updated_serial 7200 900 172800 600" /tmp/bind-dot-example-soa.txt

  kdig +https=/dns-query +tls-ca=/certs/ca.crt +tls-hostname=bind-latest @bind-latest example. SOA |
    tee /tmp/bind-doh-example-soa.txt
  grep -Eq "example\\..*[[:space:]]SOA[[:space:]]+ns1\\.example\\. hostmaster\\.example\\. $updated_serial 7200 900 172800 600" /tmp/bind-doh-example-soa.txt

  if kdig -p 853 +tls-ca=/certs/ca.crt +tls-hostname=wrong.invalid @bind-latest example. SOA >/tmp/bind-dot-wrong-host.txt 2>&1; then
    echo "FAIL: DoT accepted the wrong certificate hostname"
    exit 1
  fi
'

echo "SOA/TLD Docker acceptance passed: 2 zones, Authoritative/Recursor/BIND plaintext/DoT/DoH paths, serial increased after mutation"
