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

tools 'dig +time=2 +tries=1 @pdns-recursor missing.hns A | tee /tmp/pdns-missing-hns.txt'
tools 'grep -q "status: NXDOMAIN" /tmp/pdns-missing-hns.txt'

tools 'dig +time=2 +tries=1 @pdns-recursor example.bit A | tee /tmp/pdns-example-bit.txt'
tools 'grep -q "198.51.100.77" /tmp/pdns-example-bit.txt'

tools 'curl -fsS -X POST http://anyns-plugin-runtime:8081/api/v1/resolve -H "Content-Type: application/json" -d "{\"qname\":\"www.example.bit\",\"qtype\":\"A\",\"context\":{\"client_view\":\"default\",\"tenant\":\"default\"}}" | tee /tmp/runtime-www-example-bit.json'
tools 'grep -q "198.51.100.78" /tmp/runtime-www-example-bit.json'

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
