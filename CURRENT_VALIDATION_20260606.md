=== env GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./... ===
ok  	github.com/anyns/anyns/cmd/anyns-admin-api	(cached)
?   	github.com/anyns/anyns/cmd/anyns-config-check	[no test files]
?   	github.com/anyns/anyns/cmd/anyns-log-forwarder	[no test files]
ok  	github.com/anyns/anyns/cmd/anyns-management-key	(cached)
ok  	github.com/anyns/anyns/cmd/anyns-plugin-runtime	(cached)
ok  	github.com/anyns/anyns/internal/app	(cached)
ok  	github.com/anyns/anyns/internal/config	(cached)
ok  	github.com/anyns/anyns/internal/controlplane	(cached)
ok  	github.com/anyns/anyns/internal/dnslog	(cached)
ok  	github.com/anyns/anyns/internal/honeypot	(cached)
ok  	github.com/anyns/anyns/internal/httpapi	(cached)
ok  	github.com/anyns/anyns/internal/observability	(cached)
ok  	github.com/anyns/anyns/internal/pdnshook	(cached)
ok  	github.com/anyns/anyns/internal/plugins	(cached)
ok  	github.com/anyns/anyns/internal/plugins/hns	(cached)
ok  	github.com/anyns/anyns/internal/plugins/wave1	(cached)
ok  	github.com/anyns/anyns/internal/security	(cached)
RC=0
=== env GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./... ===
RC=0
=== env GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check ./cmd/anyns-management-key ===
RC=0
=== env GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json ===
{"admin_proxy_runtime":true,"config_file":"configs/anyns/config.example.json","dnslog_path_configured":true,"honeypot_url_configured":false,"management_auth":false,"management_keys":2,"management_roles":2,"plugins":19,"routes":19,"runtime_control_url":"http://anyns-plugin-runtime:8081","security_enabled":true,"status":"ok"}
RC=0
=== env GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json ===
{"admin_proxy_runtime":true,"config_file":"tests/docker/anyns-config.json","dnslog_path_configured":true,"honeypot_url_configured":true,"management_auth":true,"management_keys":3,"management_roles":3,"plugins":19,"routes":19,"runtime_control_url":"http://anyns-plugin-runtime:8081","security_enabled":true,"status":"ok"}
RC=0
=== bash -n tests/acceptance/check-local.sh ===
RC=0
=== bash -n tests/acceptance/runtime-smoke.sh ===
RC=0
=== bash -n tests/acceptance/docker-dns-integration.sh ===
RC=0
=== bash -n tests/acceptance/docker-hnsd-integration.sh ===
RC=0
=== python3 -m py_compile tests/docker/fixtures/backend-fixtures.py ===
RC=0
=== docker compose -f tests/docker/compose.dns-integration.yml config ===
name: anyns-dns-integration
services:
  anyns-admin-api:
    depends_on:
      anyns-plugin-runtime:
        condition: service_started
        required: true
    entrypoint:
      - /usr/local/bin/anyns-admin-api
    environment:
      ANYNS_ADMIN_ADDR: :8080
      ANYNS_CONFIG_FILE: /etc/anyns/config.json
      ANYNS_LOG_FORWARDER_ADDR: :8082
      ANYNS_RUNTIME_ADDR: :8081
    image: anyns/runtime:integration
    networks:
      dnsnet:
        aliases:
          - anyns-admin-api
    volumes:
      - type: bind
        source: /root/anyNS/tests/docker/anyns-config.json
        target: /etc/anyns/config.json
        read_only: true
        bind:
          create_host_path: true
  anyns-log-forwarder:
    depends_on:
      backend-fixtures:
        condition: service_started
        required: true
    entrypoint:
      - /usr/local/bin/anyns-log-forwarder
    environment:
      ANYNS_ADMIN_ADDR: :8080
      ANYNS_CONFIG_FILE: /etc/anyns/config.json
      ANYNS_LOG_FORWARDER_ADDR: :8082
      ANYNS_RUNTIME_ADDR: :8081
    image: anyns/runtime:integration
    networks:
      dnsnet:
        aliases:
          - anyns-log-forwarder
    volumes:
      - type: bind
        source: /root/anyNS/tests/docker/anyns-config.json
        target: /etc/anyns/config.json
        read_only: true
        bind:
          create_host_path: true
  anyns-plugin-runtime:
    build:
      context: /root/anyNS
      dockerfile: Dockerfile
    depends_on:
      backend-fixtures:
        condition: service_started
        required: true
    environment:
      ANYNS_ADMIN_ADDR: :8080
      ANYNS_CONFIG_FILE: /etc/anyns/config.json
      ANYNS_LOG_FORWARDER_ADDR: :8082
      ANYNS_RUNTIME_ADDR: :8081
    image: anyns/runtime:integration
    networks:
      dnsnet:
        aliases:
          - anyns-plugin-runtime
    volumes:
      - type: bind
        source: /root/anyNS/tests/docker/anyns-config.json
        target: /etc/anyns/config.json
        read_only: true
        bind:
          create_host_path: true
  backend-fixtures:
    command:
      - python
      - /fixtures/backend-fixtures.py
    image: python:3.12-alpine
    networks:
      dnsnet:
        aliases:
          - backend-fixtures
    volumes:
      - type: bind
        source: /root/anyNS/tests/docker/fixtures
        target: /fixtures
        read_only: true
        bind:
          create_host_path: true
  bind-latest:
    command:
      - -g
      - -c
      - /etc/bind/named.conf
    depends_on:
      pdns-recursor:
        condition: service_started
        required: true
    image: internetsystemsconsortium/bind9:9.20
    networks:
      dnsnet:
        aliases:
          - bind-latest
    volumes:
      - type: bind
        source: /root/anyNS/tests/docker/bind/named.conf
        target: /etc/bind/named.conf
        read_only: true
        bind:
          create_host_path: true
  dns-tools:
    command:
      - sleep
      - infinity
    depends_on:
      bind-latest:
        condition: service_started
        required: true
    image: alpine:3.20
    networks:
      dnsnet: null
  pdns-recursor:
    command:
      - --config-dir=/etc/powerdns
    depends_on:
      anyns-plugin-runtime:
        condition: service_started
        required: true
    environment:
      ANYNS_CLIENT_VIEW: default
      ANYNS_POLICY_TAGS: docker-integration
      ANYNS_RUNTIME_ENDPOINT: http://anyns-plugin-runtime:8081/api/v1/resolve
      ANYNS_TENANT: default
    image: powerdns/pdns-recursor-51:5.1.3
    networks:
      dnsnet:
        aliases:
          - pdns-recursor
    volumes:
      - type: bind
        source: /root/anyNS/configs/pdns-recursor
        target: /etc/powerdns
        read_only: true
        bind:
          create_host_path: true
networks:
  dnsnet:
    name: anyns-dns-integration_dnsnet
    driver: bridge
RC=0
SKIP: docker daemon is not available
RC=0
SKIP: docker daemon is not available
RC=0
runtime smoke acceptance passed on 127.0.0.1:7821
ok  	github.com/anyns/anyns/cmd/anyns-admin-api	(cached)
?   	github.com/anyns/anyns/cmd/anyns-config-check	[no test files]
?   	github.com/anyns/anyns/cmd/anyns-log-forwarder	[no test files]
ok  	github.com/anyns/anyns/cmd/anyns-management-key	(cached)
ok  	github.com/anyns/anyns/cmd/anyns-plugin-runtime	(cached)
ok  	github.com/anyns/anyns/internal/app	(cached)
ok  	github.com/anyns/anyns/internal/config	(cached)
ok  	github.com/anyns/anyns/internal/controlplane	(cached)
ok  	github.com/anyns/anyns/internal/dnslog	(cached)
ok  	github.com/anyns/anyns/internal/honeypot	(cached)
ok  	github.com/anyns/anyns/internal/httpapi	(cached)
ok  	github.com/anyns/anyns/internal/observability	(cached)
ok  	github.com/anyns/anyns/internal/pdnshook	(cached)
ok  	github.com/anyns/anyns/internal/plugins	(cached)
ok  	github.com/anyns/anyns/internal/plugins/hns	(cached)
ok  	github.com/anyns/anyns/internal/plugins/wave1	(cached)
ok  	github.com/anyns/anyns/internal/security	(cached)
RC=0
