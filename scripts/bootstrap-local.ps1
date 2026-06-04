$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root
$env:GOCACHE = if ($env:GOCACHE) { $env:GOCACHE } else { "/tmp/anyns-go-build" }

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  throw "go is required for local bootstrap"
}

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
}

go test -buildvcs=false ./...
go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder

Write-Host "Local binaries compile successfully."
Write-Host "Run Docker topology: docker compose --env-file .env up --build"
Write-Host "Runtime health: curl http://127.0.0.1:8081/healthz"
