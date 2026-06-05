#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/tests/docker/compose.dns-integration.yml"
INTEGRATION_CONFIG="$ROOT/tests/docker/anyns-config.json"
PROJECT="${ANYNS_DOCKER_PROJECT:-anyns-dns-integration}"
AUTH_HEADER='Authorization: Bearer docker-management-token'
POLICY_AUTH_HEADER='Authorization: Bearer docker-policy-token'
CACHE_AUTH_HEADER='Authorization: Bearer docker-cache-token'

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

if [[ "${ANYNS_RUN_DOCKER_DNS_INTEGRATION:-1}" != "1" ]]; then
  echo "docker DNS integration compose config passed; runtime execution disabled"
  exit 0
fi

cleanup() {
  if [[ "${ANYNS_KEEP_DOCKER_DNS_INTEGRATION:-}" != "1" ]]; then
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --build

tools() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T dns-tools sh -lc "$*"
}

tools 'apk add --no-cache bind-tools curl >/dev/null'

for _ in $(seq 1 60); do
  if tools 'curl -fsS http://anyns-plugin-runtime:8081/healthz >/dev/null && curl -fsS http://anyns-admin-api:8080/healthz >/dev/null && curl -fsS http://anyns-log-forwarder:8082/healthz >/dev/null' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! tools 'curl -fsS http://anyns-plugin-runtime:8081/healthz >/dev/null && curl -fsS http://anyns-admin-api:8080/healthz >/dev/null && curl -fsS http://anyns-log-forwarder:8082/healthz >/dev/null'; then
  echo "FAIL: anyns runtime/admin/log-forwarder did not become healthy"
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" logs --no-color anyns-plugin-runtime anyns-admin-api anyns-log-forwarder backend-fixtures pdns-recursor bind-latest || true
  exit 1
fi

tools 'status=$(curl -sS -o /tmp/admin-boundary-unauth.json -w "%{http_code}" http://anyns-admin-api:8080/api/v1/control-plane/boundary); test "$status" = "401"'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" http://anyns-admin-api:8080/api/v1/control-plane/boundary | tee /tmp/admin-boundary.json'
tools 'grep -q "\"mode\":\"admin-runtime-proxy\"" /tmp/admin-boundary.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" http://anyns-admin-api:8080/api/v1/management/keys | tee /tmp/admin-management-keys.json'
tools 'grep -q "\"auth_required\":true" /tmp/admin-management-keys.json'
tools 'grep -q "\"id\":\"docker-integration-reader\"" /tmp/admin-management-keys.json'
tools 'grep -q "\"id\":\"docker-integration-policy-writer\"" /tmp/admin-management-keys.json'
tools 'grep -q "\"id\":\"docker-integration-cache-operator\"" /tmp/admin-management-keys.json'
tools '! grep -q "docker-management-token" /tmp/admin-management-keys.json'
tools '! grep -q "docker-policy-token" /tmp/admin-management-keys.json'
tools '! grep -q "docker-cache-token" /tmp/admin-management-keys.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" http://anyns-admin-api:8080/api/v1/plugins | tee /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"hns\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"namecoin-bit\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"ens\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"stacks-bns\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"unstoppable-domains\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"pns-polkadot\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"pns-pulsechain\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"space-id\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"ton-dns\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"tezos-domains\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"aptos-names\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"suins\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"freename-fns\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"rif-rns\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"fio-handle\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"openalias\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"ada-handle\"" /tmp/admin-plugins.json'
tools 'grep -q "\"name\":\"did-bit\"" /tmp/admin-plugins.json'

tools 'status=$(curl -sS -X POST -o /tmp/admin-policy-reload-unauth.json -w "%{http_code}" http://anyns-admin-api:8080/api/v1/policies/reload); test "$status" = "401"'
tools 'status=$(curl -sS -X POST -H "'"$AUTH_HEADER"'" -o /tmp/admin-policy-reload-reader.json -w "%{http_code}" http://anyns-admin-api:8080/api/v1/policies/reload); test "$status" = "403"'
tools 'curl -fsS -X POST -H "'"$POLICY_AUTH_HEADER"'" http://anyns-admin-api:8080/api/v1/policies/reload | tee /tmp/admin-policy-reload.json'
tools 'grep -q "\"status\":\"loaded\"" /tmp/admin-policy-reload.json'
tools 'grep -q "\"name\":\"hns-fixture\"" /tmp/admin-policy-reload.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-admin-api:8080/api/v1/audit/events?source_plugin=management&matched_rule=policy.reload" | tee /tmp/admin-policy-reload-audit.json'
tools 'grep -q "\"source_plugin\":\"management\"" /tmp/admin-policy-reload-audit.json'
tools 'grep -q "\"matched_rule\":\"policy.reload\"" /tmp/admin-policy-reload-audit.json'

tools 'status=$(curl -sS -X POST -o /tmp/runtime-policy-reload-unauth.json -w "%{http_code}" http://anyns-plugin-runtime:8081/api/v1/policies/reload); test "$status" = "401"'
tools 'status=$(curl -sS -X POST -H "'"$AUTH_HEADER"'" -o /tmp/runtime-policy-reload-reader.json -w "%{http_code}" http://anyns-plugin-runtime:8081/api/v1/policies/reload); test "$status" = "403"'
tools 'curl -fsS -X POST -H "'"$POLICY_AUTH_HEADER"'" http://anyns-plugin-runtime:8081/api/v1/policies/reload | tee /tmp/runtime-policy-reload.json'
tools 'grep -q "\"status\":\"loaded\"" /tmp/runtime-policy-reload.json'
tools 'grep -q "\"name\":\"namecoin-bit-fixture\"" /tmp/runtime-policy-reload.json'
tools 'grep -q "\"name\":\"did-bit-explicit-fixture\"" /tmp/runtime-policy-reload.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?source_plugin=management&matched_rule=policy.reload" | tee /tmp/runtime-policy-reload-audit.json'
tools 'grep -q "\"source_plugin\":\"management\"" /tmp/runtime-policy-reload-audit.json'
tools 'grep -q "\"matched_rule\":\"policy.reload\"" /tmp/runtime-policy-reload-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor example.hns A | tee /tmp/pdns-example-hns.txt'
tools 'grep -q "198.51.100" /tmp/pdns-example-hns.txt'

tools 'status=$(curl -sS -o /tmp/admin-cache-stats-unauth.json -w "%{http_code}" http://anyns-admin-api:8080/api/v1/cache/stats); test "$status" = "401"'
tools 'status=$(curl -sS -H "'"$AUTH_HEADER"'" -o /tmp/admin-cache-stats-reader.json -w "%{http_code}" http://anyns-admin-api:8080/api/v1/cache/stats); test "$status" = "403"'
tools 'curl -fsS -H "'"$CACHE_AUTH_HEADER"'" http://anyns-admin-api:8080/api/v1/cache/stats | tee /tmp/admin-cache-stats.json'
tools 'grep -q "\"hns\":" /tmp/admin-cache-stats.json'
tools 'status=$(curl -sS -X POST -H "'"$AUTH_HEADER"'" -o /tmp/admin-cache-flush-reader.json -w "%{http_code}" http://anyns-admin-api:8080/api/v1/cache/flush); test "$status" = "403"'
tools 'curl -fsS -X POST -H "'"$CACHE_AUTH_HEADER"'" http://anyns-admin-api:8080/api/v1/cache/flush | tee /tmp/admin-cache-flush.json'
tools 'grep -q "\"status\":\"flushed\"" /tmp/admin-cache-flush.json'
tools 'curl -fsS -H "'"$CACHE_AUTH_HEADER"'" http://anyns-admin-api:8080/api/v1/cache/stats | tee /tmp/admin-cache-stats-after-flush.json'
tools '! grep -q "\"hns\":" /tmp/admin-cache-stats-after-flush.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-admin-api:8080/api/v1/audit/events?source_plugin=management&matched_rule=cache.flush" | tee /tmp/admin-cache-flush-audit.json'
tools 'grep -q "\"source_plugin\":\"management\"" /tmp/admin-cache-flush-audit.json'
tools 'grep -q "\"matched_rule\":\"cache.flush\"" /tmp/admin-cache-flush-audit.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-admin-api:8080/api/v1/audit/events?source_plugin=management&matched_rule=cache.flush&since=2000-01-01T00:00:00Z&until=2999-12-31T23:59:59Z" | tee /tmp/admin-cache-flush-audit-window.json'
tools 'grep -q "\"matched_rule\":\"cache.flush\"" /tmp/admin-cache-flush-audit-window.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-admin-api:8080/api/v1/audit/events?source_plugin=management&matched_rule=cache.flush&until=2000-01-01T00:00:00Z" | tee /tmp/admin-cache-flush-audit-past.json'
tools '! grep -q "\"matched_rule\":\"cache.flush\"" /tmp/admin-cache-flush-audit-past.json'
tools 'status=$(curl -sS -o /tmp/admin-audit-summary-unauth.json -w "%{http_code}" "http://anyns-admin-api:8080/api/v1/audit/summary?top_n=5"); test "$status" = "401"'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-admin-api:8080/api/v1/audit/summary?top_n=5" | tee /tmp/admin-audit-summary.json'
tools 'grep -q "\"by_plugin\"" /tmp/admin-audit-summary.json'
tools 'grep -q "\"management\":" /tmp/admin-audit-summary.json'
tools 'grep -q "\"management_mutation\":" /tmp/admin-audit-summary.json'
tools 'grep -q "\"policy.reload\":" /tmp/admin-audit-summary.json'
tools 'grep -q "\"cache.flush\":" /tmp/admin-audit-summary.json'

tools 'dig +time=2 +tries=1 @pdns-recursor missing.hns A | tee /tmp/pdns-missing-hns.txt'
tools 'grep -q "status: NXDOMAIN" /tmp/pdns-missing-hns.txt'

tools 'dig +time=2 +tries=1 @pdns-recursor example.bit A | tee /tmp/pdns-example-bit.txt'
tools 'grep -q "198.51.100.77" /tmp/pdns-example-bit.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"www.example.bit\",\"qtype\":\"A\",\"context\":{\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-www-example-bit.json'
tools 'grep -q "198.51.100.78" /tmp/runtime-www-example-bit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.did.bit TXT | tee /tmp/pdns-alice-did-bit.txt'
tools 'grep -q "did=did:bit:alice" /tmp/pdns-alice-did-bit.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.did.bit\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-did-bit-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-did-bit-wallet.json'
tools 'grep -q "\"source_plugin\":\"did-bit\"" /tmp/runtime-alice-did-bit-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-did-bit-wallet.json'
tools 'grep -q "eth 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" /tmp/runtime-alice-did-bit-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-did-bit-wallet&source_plugin=did-bit&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-did-bit-audit.json'
tools 'grep -q "alice.did.bit" /tmp/runtime-did-bit-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.eth TXT | tee /tmp/pdns-alice-eth.txt'
tools 'grep -q "alice.eth@example.test" /tmp/pdns-alice-eth.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.eth\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-ens-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-eth-wallet.json'
tools 'grep -q "\"source_plugin\":\"ens\"" /tmp/runtime-alice-eth-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-eth-wallet.json'
tools 'grep -q "eth 0x4444444444444444444444444444444444444444" /tmp/runtime-alice-eth-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-ens-wallet&source_plugin=ens&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-ens-audit.json'
tools 'grep -q "alice.eth" /tmp/runtime-ens-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.btc TXT | tee /tmp/pdns-alice-btc.txt'
tools 'grep -q "SP2DOCKERFIXTURE" /tmp/pdns-alice-btc.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.btc\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-stacks-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-btc-wallet.json'
tools 'grep -q "\"source_plugin\":\"stacks-bns\"" /tmp/runtime-alice-btc-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-btc-wallet.json'
tools 'grep -q "btc bc1qstacksfixture" /tmp/runtime-alice-btc-wallet.json'
tools 'grep -q "eth 0x3333333333333333333333333333333333333333" /tmp/runtime-alice-btc-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-stacks-wallet&source_plugin=stacks-bns&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-stacks-audit.json'
tools 'grep -q "alice.btc" /tmp/runtime-stacks-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.crypto TXT | tee /tmp/pdns-alice-crypto.txt'
tools 'grep -q "docker unstoppable fixture" /tmp/pdns-alice-crypto.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.crypto\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-unstoppable-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-crypto-wallet.json'
tools 'grep -q "\"source_plugin\":\"unstoppable-domains\"" /tmp/runtime-alice-crypto-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-crypto-wallet.json'
tools 'grep -q "eth 0x2222222222222222222222222222222222222222" /tmp/runtime-alice-crypto-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-unstoppable-wallet&source_plugin=unstoppable-domains&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-unstoppable-audit.json'
tools 'grep -q "alice.crypto" /tmp/runtime-unstoppable-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.dot TXT | tee /tmp/pdns-alice-dot.txt'
tools 'grep -q "docker pns polkadot fixture" /tmp/pdns-alice-dot.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.dot\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-pns-polkadot-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-dot-wallet.json'
tools 'grep -q "\"source_plugin\":\"pns-polkadot\"" /tmp/runtime-alice-dot-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-dot-wallet.json'
tools 'grep -q "dot 15DOTDockerFixture" /tmp/runtime-alice-dot-wallet.json'
tools 'grep -q "ksm KSMDockerFixture" /tmp/runtime-alice-dot-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-pns-polkadot-wallet&source_plugin=pns-polkadot&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-pns-polkadot-audit.json'
tools 'grep -q "alice.dot" /tmp/runtime-pns-polkadot-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.pls TXT | tee /tmp/pdns-alice-pls.txt'
tools 'grep -q "url=https://alice.pls.example.test" /tmp/pdns-alice-pls.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.pls\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-pns-pulsechain-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-pls-wallet.json'
tools 'grep -q "\"source_plugin\":\"pns-pulsechain\"" /tmp/runtime-alice-pls-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-pls-wallet.json'
tools 'grep -q "pls 0x6666666666666666666666666666666666666666" /tmp/runtime-alice-pls-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-pns-pulsechain-wallet&source_plugin=pns-pulsechain&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-pns-pulsechain-audit.json'
tools 'grep -q "alice.pls" /tmp/runtime-pns-pulsechain-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.bnb TYPE262 | tee /tmp/pdns-alice-bnb-type262.txt'
tools 'grep -q "status: NOERROR" /tmp/pdns-alice-bnb-type262.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.bnb\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-space-id-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-bnb-wallet.json'
tools 'grep -q "\"source_plugin\":\"space-id\"" /tmp/runtime-alice-bnb-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-bnb-wallet.json'
tools 'grep -q "bnb 0x7777777777777777777777777777777777777777" /tmp/runtime-alice-bnb-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-space-id-wallet&source_plugin=space-id&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-space-id-audit.json'
tools 'grep -q "alice.bnb" /tmp/runtime-space-id-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.ton TXT | tee /tmp/pdns-alice-ton.txt'
tools 'grep -q "dns_next_resolver=EQCDockerResolver" /tmp/pdns-alice-ton.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.ton\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-ton-dns-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-ton-wallet.json'
tools 'grep -q "\"source_plugin\":\"ton-dns\"" /tmp/runtime-alice-ton-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-ton-wallet.json'
tools 'grep -q "ton EQCDockerWallet" /tmp/runtime-alice-ton-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-ton-dns-wallet&source_plugin=ton-dns&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-ton-dns-audit.json'
tools 'grep -q "alice.ton" /tmp/runtime-ton-dns-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.tez TXT | tee /tmp/pdns-alice-tez.txt'
tools 'grep -q "owner=tz1DockerOwner111111111111111111111111111" /tmp/pdns-alice-tez.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.tez\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-tezos-domains-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-tez-wallet.json'
tools 'grep -q "\"source_plugin\":\"tezos-domains\"" /tmp/runtime-alice-tez-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-tez-wallet.json'
tools 'grep -q "tez tz1DockerWallet11111111111111111111111111" /tmp/runtime-alice-tez-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-tezos-domains-wallet&source_plugin=tezos-domains&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-tezos-domains-audit.json'
tools 'grep -q "alice.tez" /tmp/runtime-tezos-domains-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.apt TYPE262 | tee /tmp/pdns-alice-apt-type262.txt'
tools 'grep -q "status: NOERROR" /tmp/pdns-alice-apt-type262.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.apt\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-aptos-names-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-apt-wallet.json'
tools 'grep -q "\"source_plugin\":\"aptos-names\"" /tmp/runtime-alice-apt-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-apt-wallet.json'
tools 'grep -q "aptos 0x8888888888888888888888888888888888888888" /tmp/runtime-alice-apt-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-aptos-names-wallet&source_plugin=aptos-names&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-aptos-names-audit.json'
tools 'grep -q "alice.apt" /tmp/runtime-aptos-names-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.sui TYPE262 | tee /tmp/pdns-alice-sui-type262.txt'
tools 'grep -q "status: NOERROR" /tmp/pdns-alice-sui-type262.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.sui\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-suins-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-sui-wallet.json'
tools 'grep -q "\"source_plugin\":\"suins\"" /tmp/runtime-alice-sui-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-sui-wallet.json'
tools 'grep -q "sui 0x9999999999999999999999999999999999999999" /tmp/runtime-alice-sui-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-suins-wallet&source_plugin=suins&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-suins-audit.json'
tools 'grep -q "alice.sui" /tmp/runtime-suins-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.fns TXT | tee /tmp/pdns-alice-fns.txt'
tools 'grep -q "docker freename fixture" /tmp/pdns-alice-fns.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.fns\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-freename-fns-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-fns-wallet.json'
tools 'grep -q "\"source_plugin\":\"freename-fns\"" /tmp/runtime-alice-fns-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-fns-wallet.json'
tools 'grep -q "eth 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" /tmp/runtime-alice-fns-wallet.json'
tools 'grep -q "btc bc1qfreenamefixture" /tmp/runtime-alice-fns-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-freename-fns-wallet&source_plugin=freename-fns&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-freename-fns-audit.json'
tools 'grep -q "alice.fns" /tmp/runtime-freename-fns-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.rsk TXT | tee /tmp/pdns-alice-rsk.txt'
tools 'grep -q "url=https://alice.rsk.example.test" /tmp/pdns-alice-rsk.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.rsk\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-rif-rns-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-rsk-wallet.json'
tools 'grep -q "\"source_plugin\":\"rif-rns\"" /tmp/runtime-alice-rsk-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-rsk-wallet.json'
tools 'grep -q "rbtc 0xcccccccccccccccccccccccccccccccccccccccc" /tmp/runtime-alice-rsk-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-rif-rns-wallet&source_plugin=rif-rns&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-rif-rns-audit.json'
tools 'grep -q "alice.rsk" /tmp/runtime-rif-rns-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.safu.fio TYPE262 | tee /tmp/pdns-alice-fio-type262.txt'
tools 'grep -q "status: NOERROR" /tmp/pdns-alice-fio-type262.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.safu.fio\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-fio-handle-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-fio-wallet.json'
tools 'grep -q "\"source_plugin\":\"fio-handle\"" /tmp/runtime-alice-fio-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-fio-wallet.json'
tools 'grep -q "eth:usdt 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" /tmp/runtime-alice-fio-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-fio-handle-wallet&source_plugin=fio-handle&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-fio-handle-audit.json'
tools 'grep -q "alice.safu.fio" /tmp/runtime-fio-handle-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.openalias TXT | tee /tmp/pdns-alice-openalias.txt'
tools 'grep -q "recipient_name=Alice OpenAlias" /tmp/pdns-alice-openalias.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.openalias\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-openalias-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-openalias-wallet.json'
tools 'grep -q "\"source_plugin\":\"openalias\"" /tmp/runtime-alice-openalias-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-openalias-wallet.json'
tools 'grep -q "xmr 46BeWrHpwXmHDpDEUmZBWZfoQpdc6HaERCNmx1pEYL2rAcuwufPN9rXHHtyUA4QVy66qeFQkn6sfK8aHYjA3jk3o1Bv16em" /tmp/runtime-alice-openalias-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-openalias-wallet&source_plugin=openalias&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-openalias-audit.json'
tools 'grep -q "alice.openalias" /tmp/runtime-openalias-audit.json'

tools 'dig +time=2 +tries=1 @pdns-recursor alice.ada TXT | tee /tmp/pdns-alice-ada.txt'
tools 'grep -q "display_name=Alice ADA" /tmp/pdns-alice-ada.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"alice.ada\",\"qtype\":\"WALLET\",\"context\":{\"trace_id\":\"docker-ada-handle-wallet\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-alice-ada-wallet.json'
tools 'grep -q "\"source_plugin\":\"ada-handle\"" /tmp/runtime-alice-ada-wallet.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-alice-ada-wallet.json'
tools 'grep -q "ada addr1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" /tmp/runtime-alice-ada-wallet.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-ada-handle-wallet&source_plugin=ada-handle&rcode=NOERROR&qtype=WALLET" | tee /tmp/runtime-ada-handle-audit.json'
tools 'grep -q "alice.ada" /tmp/runtime-ada-handle-audit.json'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"wallet.hns\",\"qtype\":\"WALLET\",\"context\":{\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-wallet-hns.json'
tools 'grep -q "\"type\":\"WALLET\"" /tmp/runtime-wallet-hns.json'
tools 'grep -q "eth 0x1111111111111111111111111111111111111111" /tmp/runtime-wallet-hns.json'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"wallet.hns\",\"qtype\":\"TYPE262\",\"context\":{\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-type262-hns.json'
tools 'grep -q "\"type\":\"TYPE262\"" /tmp/runtime-type262-hns.json'
tools 'grep -q "\\\\# 23" /tmp/runtime-type262-hns.json'

tools 'dig +time=2 +tries=1 @bind-latest example.hns A | tee /tmp/bind-example-hns.txt'
tools 'grep -q "198.51.100" /tmp/bind-example-hns.txt'

tools 'dig +time=2 +tries=1 @bind-latest example.com A | tee /tmp/bind-example-com.txt'
tools 'grep -Eq "status: NOERROR|status: SERVFAIL" /tmp/bind-example-com.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"qwertyuiopasdfghjklzxcvbnm1234567890.integration\",\"qtype\":\"TXT\",\"context\":{\"trace_id\":\"docker-honeypot\",\"client_ip\":\"192.0.2.55\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-honeypot.json'
tools 'grep -q "\"action\":\"forward_to_honeypot\"" /tmp/runtime-honeypot.json'
tools 'curl -fsS http://anyns-plugin-runtime:8081/metrics | tee /tmp/runtime-metrics.txt'
tools 'grep -q "anyns_honeypot_failed_queue_length{service=\"runtime\"} 1" /tmp/runtime-metrics.txt'
tools 'status=$(curl -sS -o /tmp/runtime-audit-summary-unauth.json -w "%{http_code}" "http://anyns-plugin-runtime:8081/api/v1/audit/summary?top_n=3"); test "$status" = "401"'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/summary?top_n=3" | tee /tmp/runtime-audit-summary.json'
tools 'grep -q "\"by_plugin\"" /tmp/runtime-audit-summary.json'
tools 'grep -q "\"hns\":" /tmp/runtime-audit-summary.json'
tools 'grep -q "\"security\":" /tmp/runtime-audit-summary.json'
tools 'grep -q "\"by_rcode\"" /tmp/runtime-audit-summary.json'
tools 'grep -q "\"NOERROR\":" /tmp/runtime-audit-summary.json'
tools 'grep -q "\"forward_to_honeypot\":" /tmp/runtime-audit-summary.json'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"blocked.integration.test\",\"qtype\":\"A\",\"context\":{\"trace_id\":\"docker-denylist\",\"client_ip\":\"192.0.2.56\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-denylist.json'
tools 'grep -q "\"rcode\":\"SERVFAIL\"" /tmp/runtime-denylist.json'
tools 'grep -q "\"rule\":\"denylist-domain\"" /tmp/runtime-denylist.json'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"sinkhole.integration.test\",\"qtype\":\"A\",\"context\":{\"trace_id\":\"docker-sinkhole\",\"client_ip\":\"192.0.2.57\",\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-sinkhole.json'
tools 'grep -q "\"rcode\":\"NOERROR\"" /tmp/runtime-sinkhole.json'
tools 'grep -q "198.51.100.254" /tmp/runtime-sinkhole.json'
tools 'grep -q "\"rule\":\"sinkhole-domain\"" /tmp/runtime-sinkhole.json'

tools 'status=$(curl -sS -X POST -o /tmp/runtime-rebinding.json -w "%{http_code}" http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"private.hns\",\"qtype\":\"A\",\"context\":{\"trace_id\":\"docker-rebinding\",\"client_ip\":\"192.0.2.60\",\"client_view\":\"default\",\"tenant\":\"default\"}}"); test "$status" = "403"'
tools 'grep -q "\"rcode\":\"SERVFAIL\"" /tmp/runtime-rebinding.json'
tools 'grep -q "\"rule\":\"dns-rebinding-private-address\"" /tmp/runtime-rebinding.json'
tools '! grep -q "10.0.0.10" /tmp/runtime-rebinding.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-rebinding&source_plugin=hns&action=block&matched_rule=dns-rebinding-private-address&rcode=SERVFAIL" | tee /tmp/runtime-rebinding-audit.json'
tools 'grep -q "private.hns" /tmp/runtime-rebinding-audit.json'

tools 'status=$(curl -sS -X POST -o /tmp/runtime-reflection-rate-limit.json -w "%{http_code}" http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"reflection.integration.test\",\"qtype\":\"ANY\",\"context\":{\"trace_id\":\"docker-reflection-rate-limit\",\"client_ip\":\"192.0.2.59\",\"client_view\":\"default\",\"tenant\":\"default\"}}"); test "$status" = "429"'
tools 'grep -q "\"rcode\":\"SERVFAIL\"" /tmp/runtime-reflection-rate-limit.json'
tools 'grep -q "\"rule\":\"reflection-amplification-rr\"" /tmp/runtime-reflection-rate-limit.json'
tools 'grep -q "\"action\":\"rate_limit\"" /tmp/runtime-reflection-rate-limit.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?trace_id=docker-reflection-rate-limit&source_plugin=security&action=rate_limit&matched_rule=reflection-amplification-rr&rcode=SERVFAIL" | tee /tmp/runtime-reflection-rate-limit-audit.json'
tools 'grep -q "reflection.integration.test" /tmp/runtime-reflection-rate-limit-audit.json'

tools 'status=$(curl -sS -o /tmp/runtime-audit-unauth.json -w "%{http_code}" "http://anyns-plugin-runtime:8081/api/v1/audit/events?source_plugin=namecoin-bit"); test "$status" = "401"'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" http://anyns-plugin-runtime:8081/api/v1/audit/events?source_plugin=namecoin-bit | tee /tmp/runtime-namecoin-audit.json'
tools 'grep -q "example.bit" /tmp/runtime-namecoin-audit.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?source_plugin=namecoin-bit&since=2000-01-01T00:00:00Z&until=2999-12-31T23:59:59Z" | tee /tmp/runtime-namecoin-audit-window.json'
tools 'grep -q "example.bit" /tmp/runtime-namecoin-audit-window.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-plugin-runtime:8081/api/v1/audit/events?source_plugin=namecoin-bit&until=2000-01-01T00:00:00Z" | tee /tmp/runtime-namecoin-audit-past.json'
tools '! grep -q "example.bit" /tmp/runtime-namecoin-audit-past.json'

tools 'curl -fsS -X POST http://anyns-log-forwarder:8082/api/v1/dns-events -H "Content-Type: application/json" -d "{\"events\":[{\"trace_id\":\"docker-forwarder-event\",\"client_ip\":\"192.0.2.58\",\"client_view\":\"default\",\"tenant\":\"default\",\"qname\":\"forwarder.integration.test\",\"qtype\":\"TXT\",\"rcode\":\"NOERROR\",\"source_plugin\":\"security\",\"risk_level\":\"high\",\"action\":\"forward_to_honeypot\",\"matched_rule\":\"docker-forwarder-fixture\",\"latency_ms\":7}]}" | tee /tmp/log-forwarder-post.json'
tools 'grep -q "\"accepted\":1" /tmp/log-forwarder-post.json'
tools 'grep -q "\"forwarded\":false" /tmp/log-forwarder-post.json'
tools 'status=$(curl -sS -o /tmp/log-forwarder-audit-unauth.json -w "%{http_code}" "http://anyns-log-forwarder:8082/api/v1/audit/events?trace_id=docker-forwarder-event"); test "$status" = "401"'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-log-forwarder:8082/api/v1/audit/events?trace_id=docker-forwarder-event&source_plugin=security&action=forward_to_honeypot&matched_rule=docker-forwarder-fixture" | tee /tmp/log-forwarder-audit.json'
tools 'grep -q "forwarder.integration.test" /tmp/log-forwarder-audit.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-log-forwarder:8082/api/v1/audit/events?trace_id=docker-forwarder-event&since=2000-01-01T00:00:00Z&until=2999-12-31T23:59:59Z" | tee /tmp/log-forwarder-audit-window.json'
tools 'grep -q "forwarder.integration.test" /tmp/log-forwarder-audit-window.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-log-forwarder:8082/api/v1/audit/events?trace_id=docker-forwarder-event&until=2000-01-01T00:00:00Z" | tee /tmp/log-forwarder-audit-past.json'
tools '! grep -q "forwarder.integration.test" /tmp/log-forwarder-audit-past.json'
tools 'status=$(curl -sS -o /tmp/log-forwarder-audit-summary-unauth.json -w "%{http_code}" "http://anyns-log-forwarder:8082/api/v1/audit/summary?top_n=3"); test "$status" = "401"'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" "http://anyns-log-forwarder:8082/api/v1/audit/summary?top_n=3" | tee /tmp/log-forwarder-audit-summary.json'
tools 'grep -q "\"total\":1" /tmp/log-forwarder-audit-summary.json'
tools 'grep -q "\"security\":1" /tmp/log-forwarder-audit-summary.json'
tools 'grep -q "\"forward_to_honeypot\":1" /tmp/log-forwarder-audit-summary.json'
tools 'grep -q "forwarder.integration.test" /tmp/log-forwarder-audit-summary.json'
tools 'curl -fsS -H "'"$AUTH_HEADER"'" http://anyns-log-forwarder:8082/api/v1/honeypot/status | tee /tmp/log-forwarder-honeypot-status.json'
tools 'grep -q "\"failed_queue_length\":1" /tmp/log-forwarder-honeypot-status.json'
tools 'curl -fsS http://anyns-log-forwarder:8082/metrics | tee /tmp/log-forwarder-metrics.txt'
tools 'grep -q "anyns_dnslog_events_by_action{service=\"log-forwarder\",action=\"forward_to_honeypot\"} 1" /tmp/log-forwarder-metrics.txt'
tools 'grep -q "anyns_honeypot_failed_queue_length{service=\"log-forwarder\"} 1" /tmp/log-forwarder-metrics.txt'

echo "docker DNS integration passed"
