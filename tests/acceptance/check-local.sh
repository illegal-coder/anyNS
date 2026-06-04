#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

test -f configs/anyns/config.example.json
GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json >/tmp/anyns-config-check.json
grep -q '"status":"ok"' /tmp/anyns-config-check.json
test -f configs/pdns-recursor/recursor.lua
grep -q 'runtime_resolve' configs/pdns-recursor/recursor.lua
grep -q 'dq:addAnswer' configs/pdns-recursor/recursor.lua
bash tests/acceptance/pdns-lua-hook.sh
bash tests/acceptance/runtime-smoke.sh

GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go test -buildvcs=false ./...
GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go vet -buildvcs=false ./...
GOCACHE="${GOCACHE:-/tmp/anyns-go-build}" go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check ./cmd/anyns-management-key
