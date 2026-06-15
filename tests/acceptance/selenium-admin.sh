#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT="${ANYNS_SELENIUM_PROJECT:-anyns-selenium}"
COMPOSE=(
  docker compose
  --project-name "$PROJECT"
  --file "$ROOT/tests/docker/compose.dns-integration.yml"
  --file "$ROOT/tests/docker/compose.selenium.yml"
)

cleanup() {
  "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
build_args=(--pull)
if [[ "${ANYNS_SELENIUM_NO_CACHE:-0}" == "1" ]]; then
  build_args+=(--no-cache)
fi
"${COMPOSE[@]}" build "${build_args[@]}" anyns-plugin-runtime selenium-tests
"${COMPOSE[@]}" pull selenium-chromium
"${COMPOSE[@]}" up --abort-on-container-exit --exit-code-from selenium-tests selenium-tests