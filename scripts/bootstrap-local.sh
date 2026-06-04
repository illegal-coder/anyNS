#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export GOCACHE="${GOCACHE:-/tmp/anyns-go-build}"

if ! command -v go >/dev/null 2>&1; then
  echo "go is required for local bootstrap" >&2
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
fi

go test -buildvcs=false ./...
go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder

echo "Local binaries compile successfully."
echo "Run Docker topology: docker compose --env-file .env up --build"
echo "Runtime health: curl http://127.0.0.1:8081/healthz"
echo "HNS sample: curl -s http://127.0.0.1:8081/api/v1/resolve -d '{\"qname\":\"example.hns\",\"qtype\":\"A\",\"context\":{\"client_ip\":\"127.0.0.1\"}}' -H 'Content-Type: application/json'"
