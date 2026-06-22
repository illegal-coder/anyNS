#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

test -f configs/anyns/config.example.json
GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json >/tmp/anyns-config-check.json
grep -q '"status":"ok"' /tmp/anyns-config-check.json
test -f configs/pdns-recursor/recursor.lua
test -f configs/pdns-recursor/Dockerfile
grep -q 'runtime_resolve' configs/pdns-recursor/recursor.lua
grep -q 'dq:addAnswer' configs/pdns-recursor/recursor.lua
grep -q 'lua-cjson' configs/pdns-recursor/Dockerfile
grep -q 'lua-socket' configs/pdns-recursor/Dockerfile
bash tests/acceptance/pdns-lua-hook.sh
bash tests/acceptance/runtime-smoke.sh
GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go run -buildvcs=false ./cmd/anyns-source-policy

GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go test -buildvcs=false ./...
GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go vet -buildvcs=false ./...
GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check ./cmd/anyns-management-key ./cmd/anyns-source-policy
