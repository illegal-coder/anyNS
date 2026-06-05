# anyNS Implementation Status

Date: 2026-06-01

## Completed

This repository has moved from requirements-only documentation to a runnable first engineering skeleton while preserving `docs/`.

### P0 Foundation

- Added Go module and buildable services:
  - `cmd/anyns-plugin-runtime`
  - `cmd/anyns-admin-api`
  - `cmd/anyns-log-forwarder`
- Added PowerDNS Recursor sample config with ICANN recursive forwarding, DNSSEC validation, cache settings, and a Lua hook that can call `anyns-plugin-runtime` when LuaSocket/cjson are available.
- The Lua hook now supports configurable runtime endpoint, timeout, client view, tenant, and policy tags via `.env` / container environment:
  - `ANYNS_RUNTIME_ENDPOINT`
  - `ANYNS_RUNTIME_TIMEOUT_SECONDS`
  - `ANYNS_CLIENT_VIEW`
  - `ANYNS_TENANT`
  - `ANYNS_POLICY_TAGS`
- Added PowerDNS Authoritative sample config and `anyns.test` zone with modern RR examples:
  - `HTTPS`
  - `SVCB`
  - `TYPE262` / `WALLET` compatibility sample
- Added Docker Compose topology:
  - `pdns-recursor`
  - `pdns-authoritative`
  - `anyns-plugin-runtime`
  - `anyns-admin-api`
  - `anyns-log-forwarder`
  - optional `coredns-security` profile
- Added `.env.example`.
- Added `configs/anyns/config.example.json` and real JSON config loading for service addresses, routes, plugins, security policy thresholds/actions, DNSLog persistence, and honeypot retry/failed-queue settings.
- Added file-config plus environment override coverage for operational runtime settings after `ANYNS_CONFIG_FILE` is loaded:
  - service timeout
  - DNSLog limit/path
  - honeypot URL, credentials, failed queue path/limit, retry interval, max attempts, and request timeout
  - admin-to-runtime control proxy settings
- Added local bootstrap scripts:
  - `scripts/bootstrap-local.sh`
  - `scripts/bootstrap-local.ps1`

### P1 HNS Plugin

- Added unified plugin interface and result model.
- Added HNS sample plugin with static fixture backend for:
  - `example.hns` `A`, `AAAA`, `TXT`, `NS`
  - `wallet.hns` `WALLET` and `TYPE262`
- Added HNS success, missing-name, and `WALLET/TYPE262` tests.
- Added optional HTTP JSON backend integration for the HNS plugin while preserving the static fixture as the default local/test backend. HNS can now be configured with:
  - `plugins[].backend_url`
  - `plugins[].backend_api_key`
  - `plugins[].request_timeout`
- HNS remote backend calls use the same normalized runtime request contract as the PowerDNS Lua hook and Wave 1 backends: `plugin`, normalized `qname`, normalized `qtype`, and request `context`.
- HNS backend responses accept either `{ "result": <ResolveResult> }` envelopes or direct `ResolveResult` JSON. Backend non-2xx, request, and decode failures fail closed as `SERVFAIL` without falling back to static fixture data when a remote backend is explicitly configured.
- Added an HNS `dns://` backend mode for direct hsd/hnsd-style DNS resolver integration without requiring an intermediate HTTP adapter. When `plugins[].backend_url` is set to a value such as `dns://127.0.0.1:5350`, the HNS plugin sends a DNS wire query over UDP and maps returned `A`, `AAAA`, `NS`, `CNAME`, `TXT`, `MX`, `SRV`, `DS`, `CAA`, `TLSA`, `SVCB`, `HTTPS`, `WALLET/TYPE262`, and unknown records back into the unified `ResolveResult` contract.
- HNS `dns://` backend failures are isolated as `SERVFAIL` results with audit metadata, while `NXDOMAIN` and NODATA responses are preserved as routed runtime results so the PowerDNS Lua hook can suppress unsafe ICANN fallback for matched decentralized names.
- HNS `dns://` backend now detects truncated UDP DNS responses and retries the same query over DNS-over-TCP before mapping answers into the unified runtime contract. The result records the effective backend transport in `raw_record.backend_transport`, and unit coverage exercises the UDP-to-TCP fallback without opening sockets.

### P2 Plugin Routing Skeleton

- Added route model with suffix, tenant, client view, plugin, priority, and fallback fields.
- Added default HNS routes for `.hns` and `.hsd`.
- Added configurable route loading while preserving default HNS routing if no config file is supplied.
- Added priority-based route matching.
- Added explicit-domain route matching via `routes[].domains`, allowing exact names such as `example.hns` to override broader suffix routes by priority.
- Added route-level `policy_tags` matching, so AdGuard/audit/security-originated requests can be routed differently without changing the ICANN fallback posture.
- The PowerDNS Recursor Lua hook now forwards `ANYNS_POLICY_TAGS` into runtime requests, so policy-tagged routes can be exercised from the main PowerDNS path rather than only direct runtime callers.
- Route matching and plugin cache keys now normalize `client_view` and `tenant` casing/whitespace, keeping PowerDNS/AdGuard-originated requests on the intended runtime route even when environment values use mixed case.
- Added ICANN safety behavior: non-matching public domains are not hijacked by plugins.
- Added plugin-level TTL cache with isolation by plugin, tenant, client view, policy tags, qname, and qtype.
- Added cache flush and cache stats hooks in both the admin API and plugin runtime.
- Added app-level integration coverage proving configured routes replace defaults intentionally and enabled Wave 1 skeleton plugins fail through the routed backend boundary rather than being treated as missing routes.

### P3 Security Skeleton

- Added DNS security analyzer with initial rules for:
  - DNS tunneling / long TXT / high entropy
  - DGA-style high entropy names
  - NXDOMAIN flood tracking
  - DNS rebinding to private/local addresses
  - abnormal RR queries
  - reflection-amplification-prone RR queries
- Added DNSLog event model and in-memory audit store.
- Added configurable DNS security policy defaults for tunneling, DGA, NXDOMAIN flood, rebinding, abnormal RR, and amplification-prone RR handling.
- Added DNSLog event model with JSONL persistence and reload of recent events.
- Added honeypot API client with API key, HMAC signature, idempotency key, batch event body, and JSONL failed-delivery queue skeleton.
- Added honeypot failed-queue drain/replay support with max-attempt handling, JSONL queue rewrite after successful delivery, drop-on-exhausted-attempts behavior, and unit coverage.
- Added honeypot delivery status tracking for attempts, delivered batches, last attempt time, last error, last latency, failed queue length, oldest queued item time, and queue age.
- Added manual honeypot drain endpoints on `anyns-admin-api` and `anyns-log-forwarder` at `POST /api/v1/honeypot/drain`.
- Added honeypot status endpoints on `anyns-admin-api` and `anyns-log-forwarder` that expose retry and queue health without requiring a listening socket in unit tests.
- Added scheduled background replay workers for the honeypot failed delivery queue in:
  - `anyns-plugin-runtime`
  - `anyns-admin-api`
  - `anyns-log-forwarder`
- Background replay uses the configured retry interval, max attempts, failed queue path, and delivery timeout; unit tests cover queued delivery replay without opening a listening socket.
- Honeypot delivery status now retains cumulative replay-retained and replay-dropped batch counters after manual or background drain attempts, and admin/log-forwarder honeypot status responses expose those totals.
- Added shared Prometheus text metrics for runtime, admin API, and log forwarder:
  - `anyns_process_up`
  - `anyns_dnslog_events_buffered`
  - `anyns_dnslog_persist_last_error`
  - `anyns_dnslog_events_by_risk_level`
  - `anyns_dnslog_events_by_action`
  - `anyns_dnslog_rule_hits`
  - `anyns_dnslog_events_by_plugin`
  - `anyns_dnslog_latency_average_ms`
  - `anyns_dnslog_latency_max_ms`
  - `anyns_dnslog_plugin_latency_average_ms`
  - `anyns_dnslog_plugin_latency_max_ms`
  - `anyns_dnslog_top_client_events`
  - `anyns_dnslog_top_qname_events`
  - `anyns_honeypot_enabled`
  - `anyns_honeypot_delivery_attempts_total`
  - `anyns_honeypot_deliveries_total`
  - `anyns_honeypot_replay_retained_total`
  - `anyns_honeypot_replay_dropped_total`
  - `anyns_honeypot_failed_queue_length`
  - `anyns_honeypot_oldest_queued_age_seconds`
  - `anyns_honeypot_last_latency_ms`
- Added a no-socket runtime HTTP integration test for `POST /api/v1/resolve` that exercises HNS routing, DNSLog JSONL persistence, and honeypot failed-delivery queue persistence through the same handler path used by the PowerDNS Lua hook.
- Extended the no-socket runtime HTTP integration test to verify `/metrics` reports DNSLog retention, honeypot enablement, delivery attempts, and failed queue length after a routed resolve event.
- Extended shared Prometheus metrics to expose retained DNSLog source-plugin counts and top qname counts, making plugin hit volume and hot queried names visible from runtime/admin/log-forwarder metrics without a listening socket in tests.
- Extended DNSLog summaries and shared Prometheus metrics to expose retained RCODE distribution through `by_rcode` JSON summary data and `anyns_dnslog_events_by_rcode`, covering the architecture requirement for response-code observability without opening sockets.
- Extended DNSLog summaries and shared Prometheus metrics to expose retained latency aggregates through `latency_ms`, `latency_by_plugin_ms`, `anyns_dnslog_latency_average_ms`, `anyns_dnslog_latency_max_ms`, `anyns_dnslog_plugin_latency_average_ms`, and `anyns_dnslog_plugin_latency_max_ms`, covering no-socket plugin/runtime latency observability.
- Runtime `POST /api/v1/resolve` now enforces security `block` actions in both pre-query and post-response analysis paths. Blocked responses use the normal `ResolveResult` JSON contract, return `SERVFAIL` without leaking blocked RR answers, and record the matched security rule in DNSLog.
- Added no-socket runtime integration coverage for DNS rebinding response blocking and pre-query DGA blocking response shape.
- Added configurable security allowlist, denylist, and sinkhole domain policies:
  - `security.allowlist_domains`
  - `security.denylist_domains`
  - `security.sinkhole_domains`
  - `security.sinkhole_ipv4`
  - `security.sinkhole_ipv6`
  - `security.sinkhole_ttl`
- Runtime `POST /api/v1/resolve` now enforces denylist matches as blocked `SERVFAIL` results and sinkhole matches as `NOERROR` answers using the configured sinkhole address/TTL. Both paths write DNSLog events through the same handler path used by the PowerDNS Lua hook.
- Added config validation and no-socket tests for security list policies, sinkhole IPv4/IPv6 address-family checks, runtime denylist blocking, runtime sinkhole answers, and DNSLog event shape.
- Added configurable in-memory security rate-limit skeletons for query bursts and random subdomain attacks:
  - `security.query_rate_window_seconds`
  - `security.query_rate_threshold`
  - `security.random_subdomain_window_seconds`
  - `security.random_subdomain_threshold`
- Runtime `POST /api/v1/resolve` now enforces pre-query and post-response `rate_limit` findings as `429` responses using the same `ResolveResult` JSON contract, blocked `SERVFAIL` shape, and DNSLog append path as other security decisions.
- Added no-socket unit coverage for query-rate window expiry, random subdomain thresholding, config loading/validation of the new knobs, and runtime rate-limit DNSLog event shape.
- Added DNSLog aggregate summaries for retained audit events:
  - total events
  - counts by risk level, action, matched rule, and source plugin
  - top client IPs and qnames
- Exposed DNSLog summaries through no-socket-testable management/data-plane endpoints:
  - `GET /api/v1/audit/summary` on `anyns-admin-api`
  - `GET /api/v1/audit/summary` on `anyns-plugin-runtime`
  - `GET /api/v1/audit/summary` on `anyns-log-forwarder`
- Runtime now also exposes `GET /api/v1/audit/events` with read-scoped management auth, making data-plane DNSLog state observable without going through admin process-local state.
- `GET /api/v1/audit/events` now accepts a bounded `limit` query parameter on `anyns-admin-api`, `anyns-plugin-runtime`, and `anyns-log-forwarder`. The default remains 100 events, invalid values fall back safely, and responses are clamped to `1..1000` events to keep audit reads predictable.
- `GET /api/v1/audit/events` now accepts exact-match filters for `source_plugin`, `risk_level`, `action`, and `rcode` on `anyns-admin-api`, `anyns-plugin-runtime`, and `anyns-log-forwarder`. Filters are applied before the bounded newest-event limit, making retained DNSLog investigations narrower without opening sockets.
- `GET /api/v1/audit/events` now also accepts exact-match filters for `trace_id`, `client_ip`, `client_view`, `tenant`, `qname`, `qtype`, and `matched_rule` across `anyns-admin-api`, `anyns-plugin-runtime`, and `anyns-log-forwarder`. These filters use the same shared store and HTTP parser as the existing audit filters, and are covered by no-socket store/parser/admin/runtime tests.
- `GET /api/v1/audit/events` now accepts inclusive RFC3339 time-window filters with `since` and `until` across the shared admin/runtime/log-forwarder audit path. Invalid timestamp query values are ignored safely, filters are applied before the bounded newest-event limit, and no-socket store/parser/admin/runtime tests cover the contract.

### Wave 1 Plugin Skeletons

- Added disabled-by-default plugin skeletons for:
  - ENS `.eth`
  - Namecoin `.bit`
  - Stacks BNS `.btc` / `.stx`
  - PNS-Polkadot `.dot`
  - PNS-PulseChain `.pls`
  - Unstoppable Domains `.crypto`, `.nft`, `.wallet`, `.x`, `.dao`, `.888`, `.zil`, `.blockchain`, `.bitcoin`
- Added disabled-by-default Wave 2 runtime-json plugin skeletons for:
  - Solana SNS `.sol`
  - SPACE ID `.bnb` / `.arb`
  - TON DNS `.ton`
  - Tezos Domains `.tez`
  - Aptos Names `.apt`
  - SuiNS `.sui`
- Added sample config routes for the Wave 2 skeletons at lower priority than Wave 1 routes, preserving explicit decentralized routing and avoiding ICANN hijack for unmatched names.
- Added no-socket config/app coverage proving the Wave 2 skeletons are registered, disabled by default, and accepted by config validation using the existing runtime-json backend contract.
- Added disabled-by-default Wave 3 runtime-json plugin skeletons for:
  - Freename/FNS `.fns`
  - RIF Name Service/RNS `.rsk`
  - FIO Handle `.fio`
  - OpenAlias `.openalias`
  - ADA Handle `.ada`
  - d.id/.bit `.bit`
- Added sample config routes for Wave 3 skeletons at lower priority than Wave 1 and Wave 2 routes. The d.id/.bit route is intentionally lower priority than the Namecoin `.bit` route so `.bit` is not automatically merged and Namecoin remains the default Wave 1 `.bit` handler unless operators configure a higher-priority override.
- Added no-socket config/app/router coverage proving Wave 3 skeletons are registered, disabled by default, accepted by config validation, and preserve the Namecoin-over-d.id `.bit` conflict policy.
- Added an opt-in concrete FIO Chain API backend adapter for the `fio-handle` Wave 3 plugin:
  - `backend_type: "fio-chain-api"` posts to a FIO Chain-compatible endpoint at `/v1/chain/get_pub_address`, using `chain_code` and `token_code` query parameters from `plugins[].backend_url` and mapping DNS names like `alice.safu.fio` to the FIO Handle `alice@safu`.
  - The adapter maps returned FIO public addresses into DNS `WALLET` answers with chain/token labels while preserving `WALLET` as RR type 262 / `TYPE262` compatible output.
  - HTTP 404 and empty-address responses are preserved as routed `NXDOMAIN`; non-2xx, request, decode, and API error responses return isolated `SERVFAIL` results without leaking matched `.fio` names into ICANN fallback.
  - Config validation accepts `fio-chain-api` only on the `fio-handle` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in concrete RIF/RNS JSON-RPC backend adapter for the `rif-rns` Wave 3 plugin:
  - `backend_type: "rif-rns-json-rpc"` calls an ENS-compatible RSK JSON-RPC endpoint with `eth_call`, using an explicit `registry=<address>` query parameter on `plugins[].backend_url` for resolver lookup.
  - The adapter maps resolver `addr(bytes32)` into DNS `WALLET` answers with the `rbtc` chain label, selected `text(bytes32,string)` records into DNS `TXT`, and `contenthash(bytes32)` into DNS-safe `URI`, preserving `WALLET` as RR type 262 / `TYPE262` compatible output.
  - Names without a resolver are preserved as routed `NXDOMAIN`; missing, malformed, or zero registry configuration and JSON-RPC transport/status/decode failures return isolated `SERVFAIL` results without leaking matched `.rsk` names into ICANN fallback.
  - Config validation accepts `rif-rns-json-rpc` only on the `rif-rns` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in concrete OpenAlias DNS TXT backend adapter for the `openalias` Wave 3 plugin:
  - `backend_type: "openalias-dns-txt"` calls a configured HTTP TXT lookup adapter with `name={domain}` and `type=TXT`, then parses OpenAlias `oa1:<asset>` TXT records.
  - The adapter maps required `recipient_address` fields into DNS `WALLET` answers with the OpenAlias asset prefix, maps standard optional fields such as `recipient_name`, `tx_description`, `tx_amount`, `tx_payment_id`, `address_signature`, and `checksum` into DNS `TXT`, and preserves `WALLET` as RR type 262 / `TYPE262` compatible output.
  - Missing OpenAlias TXT records are preserved as routed `NXDOMAIN`; non-2xx, request, and decode failures return isolated `SERVFAIL` results without leaking matched `.openalias` names into ICANN fallback.
  - Config validation accepts `openalias-dns-txt` only on the `openalias` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in concrete ADA Handle public API backend adapter for the `ada-handle` Wave 3 plugin:
  - `backend_type: "ada-handle-api"` calls a configured ADA Handle-compatible base URL such as `https://api.handle.me` at `/handles/{handle}`.
  - The adapter maps Cardano payment/holder address fields into DNS `WALLET` answers with the `ada` chain label, maps simple Handle/profile metadata into `TXT`, maps image/profile URLs into `URI`, and preserves `WALLET` as RR type 262 / `TYPE262` compatible output.
  - Empty/404 responses are preserved as routed `NXDOMAIN`; non-2xx, request, and decode failures return isolated `SERVFAIL` results without leaking matched `.ada` names into ICANN fallback.
  - Config validation accepts `ada-handle-api` only on the `ada-handle` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in concrete Freename Resolution API backend adapter for the `freename-fns` Wave 3 plugin:
  - `backend_type: "freename-resolution-api"` calls a Freename-compatible base URL such as `https://rslvr.freename.io` at `/domain/resolve?q={domain}`.
  - The adapter maps Freename `token.*` records into DNS `WALLET` answers, website redirects into `URI`, TXT records into `TXT`, and profile fields into DNS-safe `TXT`, preserving `WALLET` as RR type 262 / `TYPE262` compatible output.
  - Empty record sets and HTTP 404 responses are preserved as routed `NXDOMAIN`; non-2xx, request, and decode failures return isolated `SERVFAIL` results without leaking matched `.fns` names into ICANN fallback.
  - Config validation accepts `freename-resolution-api` only on the `freename-fns` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in concrete Solana SNS QuickNode JSON-RPC backend adapter for the `solana-sns` Wave 2 plugin:
  - `backend_type: "solana-sns-quicknode"` posts JSON-RPC requests to a QuickNode Solana endpoint with the SNS marketplace plugin enabled, using the `sns_resolveDomain` method.
  - The adapter maps resolved `.sol` public keys into DNS `WALLET` answers with the `sol` chain label while preserving `WALLET` as RR type 262 / `TYPE262` compatible output.
  - Empty or not-found responses are preserved as routed `NXDOMAIN`; HTTP, decode, and JSON-RPC backend failures return isolated `SERVFAIL` results without leaking matched `.sol` names into ICANN fallback.
  - Config validation accepts `solana-sns-quicknode` only on the `solana-sns` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in concrete TON Center v3 DNS records backend adapter for the `ton-dns` Wave 2 plugin:
  - `backend_type: "toncenter-v3-dns"` calls a TON Center-compatible base URL such as `https://toncenter.com` at `/api/v3/dns/records?domain={domain}`.
  - The adapter maps `.ton` wallet records into DNS `WALLET` answers with the `ton` chain label, maps TON Site ADNL and TON Storage Bag IDs into `URI`, and maps next resolver / NFT metadata into `TXT`.
  - Empty record sets and HTTP 404 responses are preserved as routed `NXDOMAIN`; non-2xx, request, decode, and API error responses return isolated `SERVFAIL` results without leaking matched `.ton` names into ICANN fallback.
  - Config validation accepts `toncenter-v3-dns` only on the `ton-dns` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in concrete SPACE ID Web3 Name API backend adapter for the `space-id` Wave 2 plugin:
  - `backend_type: "space-id-api"` calls a SPACE ID-compatible HTTP API base URL such as `https://nameapi.space.id` at `/getAddress?domain={domain}`.
  - The adapter maps `.bnb` and `.arb` resolved addresses into DNS `WALLET` answers with chain labels while preserving `WALLET` as RR type 262 / `TYPE262` compatible output.
  - Missing address responses are preserved as routed `NXDOMAIN`; non-2xx, request, decode, and API error responses return isolated `SERVFAIL` results without leaking matched SPACE ID names into ICANN fallback.
  - Config validation accepts `space-id-api` only on the `space-id` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in concrete Tezos Domains GraphQL backend adapter for the `tezos-domains` Wave 2 plugin:
  - `backend_type: "tezos-domains-api"` posts GraphQL requests to a Tezos Domains-compatible endpoint such as `https://api.tezos.domains/graphql`.
  - The adapter maps Tezos address ownership into DNS `WALLET` answers with the `tez` chain label, maps selected profile/text records into `TXT`, maps URL/content records into `URI`, and accepts DNS-style `A`, `AAAA`, `CNAME`, `NS`, and `TXT` keys when exposed by the API.
  - Missing domain responses are preserved as routed `NXDOMAIN`; non-2xx, request, decode, and GraphQL error responses return isolated `SERVFAIL` results without leaking matched `.tez` names into ICANN fallback.
  - Config validation accepts `tezos-domains-api` only on the `tezos-domains` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in concrete Aptos Names REST backend adapter for the `aptos-names` Wave 2 plugin:
  - `backend_type: "aptos-names-api"` calls an Aptos Names-compatible REST base URL such as `https://www.aptosnames.com/api/mainnet` at `/v3/address/{name}`.
  - The adapter sends API credentials using the documented `X-API-Key` header, maps resolved `.apt` addresses into DNS `WALLET` answers with the `aptos` chain label, and preserves `WALLET` as RR type 262 / `TYPE262` compatible output.
  - HTTP 404 and empty-address responses are preserved as routed `NXDOMAIN`; non-2xx, request, decode, and API error responses return isolated `SERVFAIL` results without leaking matched `.apt` names into ICANN fallback.
  - Config validation accepts `aptos-names-api` only on the `aptos-names` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in concrete SuiNS JSON-RPC backend adapter for the `suins` Wave 2 plugin:
  - `backend_type: "suins-json-rpc"` posts Sui JSON-RPC requests to a configured Sui fullnode endpoint using `suix_resolveNameServiceAddress`.
  - The adapter maps resolved `.sui` addresses into DNS `WALLET` answers with the `sui` chain label while preserving `WALLET` as RR type 262 / `TYPE262` compatible output.
  - Null or empty address results are preserved as routed `NXDOMAIN`; HTTP, decode, and JSON-RPC backend failures return isolated `SERVFAIL` results without leaking matched `.sui` names into ICANN fallback.
  - Config validation accepts `suins-json-rpc` only on the `suins` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added sample config routes for HNS and all current Wave 1 skeleton plugins.
- Added configurable HTTP JSON backend integration for Wave 1 plugins. Each Wave 1 plugin can now be enabled with:
  - `plugins[].backend_url`
  - `plugins[].backend_api_key`
  - `plugins[].request_timeout`
- Wave 1 backend calls use the same normalized `qname`, `qtype`, and request context shape as the PowerDNS Lua hook to runtime path, and preserve failure isolation by returning `SERVFAIL` plus audit metadata when the backend is unavailable or returns a non-2xx response.
- Wave 1 backend responses accept either `{ "result": <ResolveResult> }` envelopes or direct `ResolveResult` JSON, making ENS, Namecoin `.bit`, Stacks BNS, PNS-Polkadot, PNS-PulseChain, and Unstoppable adapters pluggable without changing the runtime routing contract.
- Updated `configs/anyns/config.example.json` with disabled-by-default Wave 1 backend configuration placeholders.
- Added an opt-in real Namecoin `.bit` JSON-RPC backend adapter for the `namecoin-bit` Wave 1 plugin:
  - `plugins[].backend_type` selects backend behavior while preserving the existing generic runtime JSON adapter as `runtime-json`.
  - `backend_type: "namecoin-json-rpc"` calls a Namecoin Core-compatible `name_show d/<name>` endpoint over HTTP(S), supports Basic auth via `backend_api_key` values shaped as `user:password`, maps Namecoin JSON values into standard `A`, `AAAA`, `NS`, `TXT`, and `CNAME` records, handles `map` subdomain records, and preserves Namecoin not-found responses as routed `NXDOMAIN` instead of leaking into ICANN fallback.
  - Config validation rejects unsupported backend types and only allows `namecoin-json-rpc` on the `namecoin-bit` plugin.
- Added an opt-in real Unstoppable Domains Resolution Service backend adapter for the `unstoppable-domains` Wave 1 plugin:
  - `backend_type: "unstoppable-resolution-api"` calls a configured Resolution Service base URL such as `https://api.unstoppabledomains.com/resolve` at `/domains/{domain}` with optional Bearer auth.
  - The adapter maps returned records into DNS-safe `A`, `AAAA`, `CNAME`, `TXT`, `URI`, and `WALLET` answers, including `crypto.*.address` wallet records for `.wallet`-style needs while preserving `WALLET` as RR type 262.
  - HTTP 404 responses are preserved as routed `NXDOMAIN`; other non-2xx, request, and decode failures return isolated `SERVFAIL` results without leaking matched decentralized names into ICANN fallback.
  - Config validation accepts `unstoppable-resolution-api` only on the `unstoppable-domains` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in real Stacks BNS API backend adapter for the `stacks-bns` Wave 1 plugin:
  - `backend_type: "stacks-bns-api"` calls a Stacks/Hiro-compatible API base URL such as `https://api.mainnet.hiro.so/v1` at `/names/{name}/zonefile` with optional Bearer auth.
  - The adapter maps legacy BNS zonefile records into `A`, `AAAA`, `CNAME`, `TXT`, `NS`, `MX`, `SRV`, `URI`, `HTTPS`, `SVCB`, `TLSA`, and `CAA` answers, and maps BNSv2 JSON zonefile profile/address fields into `TXT`, `URI`, and `WALLET`.
  - HTTP 404 responses are preserved as routed `NXDOMAIN`; other non-2xx, request, read, and decode failures return isolated `SERVFAIL` results without leaking matched `.btc` / `.stx` names into ICANN fallback.
  - Config validation accepts `stacks-bns-api` only on the `stacks-bns` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in real ENS JSON-RPC backend adapter for the `ens` Wave 1 plugin:
  - `backend_type: "ens-json-rpc"` calls an Ethereum JSON-RPC endpoint with `eth_call`, first resolving the configured `.eth` name through the ENS Registry resolver lookup and then querying standard resolver `addr(bytes32)`, `text(bytes32,string)`, and `contenthash(bytes32)` methods.
  - The adapter maps ETH address records into DNS `WALLET` answers, selected ENS text records into DNS `TXT`, and contenthash bytes into DNS-safe `URI` values, preserving `WALLET` as RR type 262 / `TYPE262` compatible output.
  - Names without a resolver are preserved as routed `NXDOMAIN`; JSON-RPC transport/status/decode failures return isolated `SERVFAIL` results without leaking matched `.eth` names into ICANN fallback.
  - Config validation accepts `ens-json-rpc` only on the `ens` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in real PulseChain PNS JSON-RPC backend adapter for the `pns-pulsechain` Wave 1 plugin:
  - `backend_type: "pulsechain-pns-json-rpc"` calls a PulseChain/EVM JSON-RPC endpoint with `eth_call`, using an explicit `registry=<address>` query parameter on `plugins[].backend_url` for ENS-compatible resolver lookup.
  - The adapter maps resolver `addr(bytes32)` into DNS `WALLET` answers with `pls` chain labels, selected `text(bytes32,string)` records into DNS `TXT`, and `contenthash(bytes32)` into DNS-safe `URI`, preserving `WALLET` as RR type 262 / `TYPE262` compatible output.
  - Names without a resolver are preserved as routed `NXDOMAIN`; missing, malformed, or zero registry configuration and JSON-RPC transport/status/decode failures return isolated `SERVFAIL` results without leaking matched `.pls` names into ICANN fallback.
  - Config validation accepts `pulsechain-pns-json-rpc` only on the `pns-pulsechain` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.
- Added an opt-in real PNS-Polkadot REST backend adapter for the `pns-polkadot` Wave 1 plugin:
  - `backend_type: "pns-polkadot-api"` calls a PNS-compatible REST API base URL such as `https://api.ddns.so` at `/name/{name}`.
  - The adapter maps PNS record fields into DNS-safe `A`, `AAAA`, `CNAME`, `TXT`, `URI`, and `WALLET` answers, including `.dot` wallet records and multi-network wallet maps while preserving `WALLET` as RR type 262 / `TYPE262` compatible output.
  - HTTP 404 responses are preserved as routed `NXDOMAIN`; other non-2xx, request, and decode failures return isolated `SERVFAIL` results without leaking matched `.dot` names into ICANN fallback.
  - Config validation accepts `pns-polkadot-api` only on the `pns-polkadot` plugin, and `configs/anyns/config.example.json` demonstrates the disabled-by-default adapter.

### Management / Runtime Boundary

- Added `/api/v1/control-plane/boundary` to document the current process-local admin/runtime state boundary.
- Added `internal/controlplane` shared HTTP handlers for plugin listing, plugin enable/disable, cache flush, cache stats, and boundary reporting.
- `anyns-plugin-runtime` now exposes live data-plane control endpoints:
  - `GET /api/v1/plugins`
  - `POST /api/v1/plugins/{name}/enable`
  - `POST /api/v1/plugins/{name}/disable`
  - `POST /api/v1/cache/flush`
  - `GET /api/v1/cache/stats`
- Admin and runtime still load the same config shape. The Go library default remains process-local for local development, while the shipped Compose/example deployment now enables admin-to-runtime proxying so admin-side plugin/cache mutations target the live runtime data plane.
- Added unit tests proving runtime control endpoints mutate the live registry and clear the live cache.
- Added optional admin-to-runtime control proxying:
  - `control_plane.admin_proxy_runtime`
  - `control_plane.runtime_control_url`
  - `ANYNS_ADMIN_PROXY_RUNTIME_CONTROL`
  - `ANYNS_RUNTIME_CONTROL_URL`
- When proxying is enabled, admin API plugin listing, plugin enable/disable, cache flush, and cache stats are forwarded to the runtime control endpoints. `configs/anyns/config.example.json` and `.env.example` now set this mode as the deployment default.
- `/api/v1/control-plane/boundary` now reports `admin-runtime-proxy` when this mode is enabled.
- Config validation now rejects `control_plane.admin_proxy_runtime=true` unless `control_plane.runtime_control_url` is a valid `http` or `https` URL with a host, and `anyns-config-check` reports the effective control-plane proxy fields.
- Added optional Bearer-token authentication for management/control-plane endpoints:
  - `management.auth_required`
  - `management.api_key`
  - `ANYNS_MANAGEMENT_AUTH_REQUIRED`
  - `ANYNS_MANAGEMENT_API_KEY`
- Management authentication defaults to disabled for local development compatibility. When enabled, admin API audit/policy/honeypot endpoints and runtime/admin control-plane endpoints require `Authorization: Bearer <api-key>`.
- Admin-to-runtime proxying preserves the `Authorization` header so an authenticated admin request can reach an authenticated runtime control plane.
- Added scoped management keys while preserving the legacy single API key:
  - `management.keys[].id`
  - `management.keys[].api_key`
  - `management.keys[].scopes`
- Management scopes currently support `read`, `write`, `admin`, and `*`. Read-scoped keys can list plugins, cache stats, boundary state, audit events, and honeypot status; write-scoped keys are required for plugin enable/disable, cache flush, policy reload, and honeypot drain. The legacy `management.api_key` remains read/write for backward compatibility.
- Applied the same scoped management gate to log-forwarder audit and honeypot status/drain endpoints.
- Added optional management key rotation windows with `management.keys[].not_before` and `management.keys[].expires_at`. Config validation checks RFC3339 syntax and ordering, while request authentication ignores expired keys and keys that are not active yet.
- Added read-scoped management key rotation observability on admin/runtime control-plane handlers:
  - `GET /api/v1/management/keys`
  - Reports auth enablement, configured/active key counts, legacy key presence, key IDs, scopes, rotation timestamps, and `active` / `not_yet_active` / `expired` status.
  - Does not expose API key/token material.
- Added optional management key client binding with `management.keys[].allowed_client_cidrs`.
  - Scoped management keys can now be restricted to exact client IPs or CIDR ranges before scope checks are applied.
  - Config validation rejects malformed IP/CIDR entries.
  - `GET /api/v1/management/keys` reports whether client restrictions are enabled and how many CIDRs are configured without exposing the CIDR values or token material.
- Added fine-grained management key scopes while preserving the existing coarse `read` / `write`, `admin`, and `*` scopes:
  - `plugins:read`, `plugins:write`
  - `cache:read`, `cache:write`
  - `policy:write`
  - `audit:read`
  - `honeypot:read`, `honeypot:write`
  - `management:read`, `management:write`
  - Config validation accepts the fine-grained scope names, and `configs/anyns/config.example.json` now demonstrates separated read/write operational keys without exposing token material.
- Added management RBAC role templates while preserving direct key scopes:
  - `management.roles[].id`
  - `management.roles[].scopes`
  - `management.keys[].roles`
  - Config validation rejects duplicate role IDs, empty role scope bundles, unsupported role scopes, and keys that reference missing roles.
  - Runtime/admin/log-forwarder auth expands direct key scopes plus assigned role-template scopes before endpoint authorization.
  - `GET /api/v1/management/keys` reports configured role templates and role-backed key metadata without exposing token material or CIDR values.
- Extended `GET /api/v1/management/keys` with redacted lifecycle automation metadata:
  - `expires_in_seconds`
  - `rotation_due`
  - `has_overlapping_successor`
  - `lifecycle_action`
  - `rotation_warning_hours`
  - The endpoint now flags expired keys for removal, keys without expiry windows for lifecycle hardening, and expiring keys that lack a same-scope overlapping successor.
- Added explicit management key revocation support with `management.keys[].revoked_at`.
  - Config validation checks RFC3339 revocation timestamps.
  - Runtime/admin/log-forwarder auth rejects revoked scoped keys without exposing token material.
  - `GET /api/v1/management/keys` reports `revoked_at`, `status=revoked`, and `lifecycle_action=remove_revoked_key`.
- Added `cmd/anyns-management-key` for deployment-backed JSON config lifecycle operations:
  - `generate` appends a scoped or role-backed management key, generates a random API token when one is not supplied, validates the updated config, writes it back to disk, and prints the generated token once.
  - `revoke` marks an existing key with `revoked_at`, validates the updated config, writes it back to disk, and does not print token material.
- `anyns-management-key generate` and `revoke` can now optionally orchestrate a live control-plane reload after a durable config mutation:
  - `--reload-url` accepts an admin or runtime base URL, or the full `/api/v1/policies/reload` endpoint.
  - `--reload-api-key` forwards a Bearer token for authenticated reload endpoints.
  - `--reload-timeout` bounds the reload request.
  - Command output reports whether reload was attempted and the HTTP status when it succeeds. If reload fails, the validated config mutation remains durable and the command surfaces the reload error so operators can retry the reload explicitly.
- `anyns-management-key status` now queries a live admin or runtime `/api/v1/management/keys` endpoint and emits a redacted lifecycle action plan for keys requiring rotation, expiry cleanup, or revocation cleanup without exposing token material.
  - `--url` accepts an admin/runtime base URL or the full management-key metadata endpoint.
  - `--api-key` forwards a Bearer token for authenticated metadata endpoints.
  - `--timeout` bounds the live status request.
- `anyns-management-key rotate` now creates a guarded successor key from an existing scoped or role-backed key:
  - Copies the source key's scopes, roles, and allowed client CIDRs without exposing the old token.
  - Generates or accepts a one-time successor token, sets `not_before` and `expires_at`, validates the updated JSON config, and writes the durable mutation.
  - Can query a live `/api/v1/management/keys` endpoint before writing and refuses to create duplicate overlapping successors unless `--force` is set.
  - Reuses the existing optional live reload orchestration through `--reload-url`, `--reload-api-key`, and `--reload-timeout`.
- Management key CLI reload orchestration now accepts repeated `--reload-url` flags on `generate`, `revoke`, and `rotate`, so operators can reload both admin and runtime control planes after one durable config mutation. Single-target output preserves the previous top-level reload fields; multi-target output reports per-endpoint results.
- Added file-backed secret references for deployment configs so operators do not need to place token material directly in JSON config:
  - `plugins[].backend_api_key_file`
  - `honeypot.api_key_file`
  - `honeypot.hmac_secret_file`
  - `management.api_key_file`
  - `management.keys[].api_key_file`
  - Secret file paths resolve relative to the config file location when loaded from `ANYNS_CONFIG_FILE` / `LoadFile`, are trimmed of surrounding whitespace, reject empty files, and reject setting both inline and file-backed values for the same secret.
  - Runtime consumers still receive the resolved credential through the existing config fields, preserving current plugin backend, honeypot, and management auth contracts.
- `POST /api/v1/policies/reload` now performs a real config-file reload instead of returning a static success response. It reloads the configured file with environment overrides, rebuilds process-local route/plugin/security/DNSLog/honeypot state, and returns the effective routes, plugin config, and security policy.
- The same reload endpoint is exposed by `anyns-plugin-runtime`, so deployments can refresh the live PowerDNS data-plane process directly without relying on admin API process-local state.
- Added no-socket tests proving admin reload and runtime reload update live route matching, enabled Wave 1 skeleton plugin behavior, and security-policy decisions.
- `anyns-admin-api`, `anyns-plugin-runtime`, and `anyns-log-forwarder` now validate effective config before opening listening sockets, so route/plugin/security/DNSLog/honeypot integration errors caught by `anyns-config-check` are also rejected by real service startup.
- Admin and runtime `POST /api/v1/policies/reload` now validate the reloaded config before mutating live process state. Invalid reloads return an error, preserve the previous registry/security/DNSLog state, and do not write a successful management audit event.
- Added management mutation audit events for plugin enable/disable, cache flush, policy reload, and admin honeypot drain. These events are written to the same DNSLog store, use `source_plugin=management`, preserve the scoped management key id, and persist through the configured DNSLog JSONL path.
- Control-plane handlers now read the live config reference owned by admin/runtime mux setup. After `POST /api/v1/policies/reload`, plugin control, cache, boundary, and management auth decisions use the reloaded config instead of the registration-time copy.

### P4 Delivery Assets

- Added runnable deployment assets and acceptance script:
  - `docker-compose.yml`
  - `Dockerfile`
  - `configs/pdns-recursor/`
  - `configs/pdns-authoritative/`
  - `configs/coredns/`
  - `tests/acceptance/hns-resolve.sh`
  - `tests/acceptance/check-local.sh`
- Added `tests/acceptance/pdns-lua-hook.sh` to validate the PowerDNS Recursor Lua hook without requiring a listening socket; it checks runtime dependency fallback behavior, policy-tag forwarding, optionally runs `luac -p`, and renders Docker Compose config when Docker Compose is available. If root `.env` is absent, the script creates a temporary `.env` from `.env.example` and removes it after rendering.
- Added Go-level PowerDNS Recursor Lua hook contract tests in `internal/pdnshook` covering runtime request shape, environment knobs, safe ICANN fallback behavior, non-honeypot HMAC separation, and explicit `WALLET/TYPE262` handling notes.
- Tightened the PowerDNS Recursor Lua hook integration so routed runtime `NOERROR`, `NXDOMAIN`, and `SERVFAIL` results are applied to `dq.rcode` and return `true`, preventing decentralized suffix misses or plugin failures from leaking into ICANN fallback. `NOERROR` with no RR answers is treated as routed NODATA, while invalid JSON and non-contract HTTP statuses such as no-route `404` still preserve safe ICANN recursion fallback.
- Extended the PowerDNS Recursor Lua hook RR mapping for additional records used by decentralized and DNSSEC-aware backends: `DS`, `TLSA`, `SVCB`, and `HTTPS`. Target images that do not expose a matching PowerDNS Lua constant keep the existing unsupported-RR log path.
- Hardened the PowerDNS Recursor Lua hook to normalize runtime-returned RR types and RCODEs before mapping them, so external runtime-json adapters or decentralized backends that return lowercase/mixed-case `type` or `rcode` fields still follow the same routed PowerDNS behavior without unsafe ICANN fallback leakage.
- Hardened the PowerDNS Recursor Lua hook to honor valid runtime `ResolveResult` bodies returned with security decision statuses `403` and `429`, so runtime-enforced block and rate-limit decisions suppress ICANN fallback on the PowerDNS path while unmatched public-domain no-route `404` responses still fall through to normal ICANN recursion.
- Added no-socket runtime coverage proving a missing HNS name returns a routed `NXDOMAIN` result with `source_plugin=hns`, records a DNSLog event, and remains visible to the Lua hook as an HTTP 200 runtime response rather than a no-route fallback.
- Added reusable config validation plus a no-socket `anyns-config-check` command. The check validates loaded route/plugin references, management key shape and scopes, DNSLog retention settings, honeypot retry/failed-queue settings, and service timeout/address basics before services are started.
- Config validation now rejects unsupported plugin backend URL schemes and accepts `http`, `https`, and `dns` backends, covering both the existing JSON runtime adapter contract and the new direct HNS DNS resolver integration.
- `tests/acceptance/check-local.sh` now validates `configs/anyns/config.example.json` with `anyns-config-check` and builds the checker alongside the three long-running services.
- `tests/acceptance/check-local.sh` now also builds `anyns-management-key` so the management lifecycle CLI remains covered by local no-socket validation.
- Added `tests/acceptance/runtime-smoke.sh`, a real runtime acceptance smoke that builds `anyns-plugin-runtime`, starts it with a temporary JSON config, verifies HNS resolution over the HTTP runtime API, triggers a high-entropy TXT query, and checks DNSLog JSONL plus honeypot failed-queue persistence and metrics.
- `tests/acceptance/check-local.sh` now runs the runtime smoke after the PowerDNS Lua hook contract check. In socket-restricted environments, the smoke exits successfully with a clear `SKIP` reason instead of masking sandbox limitations as application failures.
- Added deterministic Docker DNS integration fixtures:
  - `tests/docker/anyns-config.json` configures HNS through a runtime-json fixture backend and Namecoin `.bit` through a fake Namecoin Core JSON-RPC backend.
  - `tests/docker/fixtures/backend-fixtures.py` serves no-secret HNS runtime-json responses, Namecoin `name_show` JSON-RPC responses, and a failing honeypot endpoint for queue tests.
  - `tests/docker/compose.dns-integration.yml` now includes a `backend-fixtures` container and mounts the dedicated integration config instead of the broad sample config.
  - `tests/acceptance/docker-dns-integration.sh` now validates the integration config, asserts strict HNS `NXDOMAIN`, checks PowerDNS-routed `.bit`, checks runtime-routed Namecoin subdomain data, and verifies Namecoin audit events.
- Extended `tests/acceptance/docker-dns-integration.sh` with deterministic runtime assertions for:
  - `wallet.hns` `WALLET` answers.
  - `wallet.hns` `TYPE262` RFC3597-compatible answers.
  - DNS tunneling/high-entropy `TXT` detection flowing to the failing honeypot fixture and surfacing as `anyns_honeypot_failed_queue_length` in runtime metrics.
- Extended the deterministic Docker DNS integration topology and script with:
  - `anyns-admin-api` in the isolated Docker network, using the same fixture config and admin-to-runtime proxy default.
  - Admin health, `/api/v1/control-plane/boundary`, and proxied plugin listing assertions for `hns` and `namecoin-bit`.
  - Runtime security denylist and sinkhole assertions using the configured `blocked.integration.test` and `sinkhole.integration.test` policies.
- Extended the deterministic Docker DNS integration topology and script with `anyns-log-forwarder` as a first-class service. The Docker acceptance script now waits for log-forwarder health, posts a deterministic DNSLog event to `/api/v1/dns-events`, verifies filtered audit-event retrieval, and checks log-forwarder Prometheus metrics plus failed honeypot queue behavior through the same failing fixture endpoint.
- Extended the deterministic Docker DNS integration config and script with fixture-scoped management auth roles for read, policy-write, and cache-read/write operations. The Docker acceptance script now asserts unauthenticated/under-scoped rejection, redacted management-key metadata, admin/runtime policy reload audit events, admin-to-runtime proxied cache stats, cache flush, and cache-flush management audit visibility.
- Extended the deterministic Docker DNS integration script with authenticated audit-summary assertions for admin, runtime, and log-forwarder. The script now checks unauthenticated `401` behavior plus aggregate management mutation, plugin, RCODE, and action totals after management, HNS, security, honeypot, and log-forwarder fixture events are generated.
- Extended the deterministic Docker DNS integration script with authenticated audit time-window assertions for admin, runtime, and log-forwarder audit reads. The script now proves known fixture events are returned inside a broad inclusive RFC3339 `since` / `until` window and excluded when the requested window ends before the event.
- Extended the deterministic Docker DNS integration fixture and script with a post-response DNS rebinding assertion. The HNS fixture now serves `private.hns A` as `10.0.0.10`, and the Docker acceptance script asserts the runtime returns HTTP `403`, a blocked `SERVFAIL` `ResolveResult`, no leaked private answer, `dns-rebinding-private-address`, and an authenticated audit event with `source_plugin=hns`.
- Extended the deterministic Docker DNS integration fixture path with an enabled Unstoppable Domains adapter fixture. The Docker config now routes `.crypto` through `unstoppable-domains` using the existing `unstoppable-resolution-api` backend contract, the fixture serves deterministic `alice.crypto` records, and the acceptance script asserts admin plugin visibility, PowerDNS-routed `TXT` resolution, runtime `WALLET` mapping, and authenticated audit visibility without live API keys.
- Extended the deterministic Docker DNS integration fixture path with an enabled Stacks BNS adapter fixture. The Docker config now routes `.btc` / `.stx` through `stacks-bns` using the existing `stacks-bns-api` backend contract, the fixture serves deterministic `alice.btc` JSON-zonefile data, and the acceptance script asserts admin plugin visibility, PowerDNS-routed `TXT` resolution, runtime `WALLET` mapping, and authenticated audit visibility without live Hiro/Stacks API keys.
- Extended the deterministic Docker DNS integration fixture path with an enabled PNS-Polkadot adapter fixture. The Docker config now routes `.dot` through `pns-polkadot` using the existing `pns-polkadot-api` backend contract, the fixture serves deterministic `alice.dot` wallet, TXT, URI, and address data, and the acceptance script asserts admin plugin visibility, PowerDNS-routed `TXT` resolution, runtime `WALLET` mapping, and authenticated audit visibility without live PNS API keys.
- Extended the deterministic Docker DNS integration fixture path with an enabled ENS adapter fixture. The Docker config now routes `.eth` through `ens` using the existing `ens-json-rpc` backend contract, the fixture serves deterministic Ethereum JSON-RPC `eth_call` responses for resolver lookup, wallet address, text records, and contenthash, and the acceptance script asserts admin plugin visibility, PowerDNS-routed `TXT` resolution, runtime `WALLET` mapping, and authenticated audit visibility without live Ethereum RPC credentials.
- Extended the deterministic Docker DNS integration fixture path with an enabled PulseChain PNS adapter fixture. The Docker config now routes `.pls` through `pns-pulsechain` using the existing `pulsechain-pns-json-rpc` backend contract, the fixture serves deterministic ENS-compatible PulseChain JSON-RPC `eth_call` responses for registry resolver lookup, wallet address, text records, and contenthash, and the acceptance script asserts admin plugin visibility, PowerDNS-routed `TXT` resolution, runtime `WALLET` mapping, and authenticated audit visibility without live PulseChain RPC credentials.
- Extended the deterministic Docker DNS integration fixture path with an enabled SPACE ID adapter fixture. The Docker config now routes `.bnb` / `.arb` through `space-id` using the existing `space-id-api` backend contract, the fixture serves deterministic `/getAddress?domain=alice.bnb` responses, and the acceptance script asserts admin plugin visibility, PowerDNS routed `TYPE262` posture, runtime `WALLET` mapping, and authenticated audit visibility without live SPACE ID API credentials.
- Extended the deterministic Docker DNS integration fixture path with an enabled TON DNS adapter fixture. The Docker config now routes `.ton` through `ton-dns` using the existing `toncenter-v3-dns` backend contract, the fixture serves deterministic `/api/v3/dns/records?domain=alice.ton` responses, and the acceptance script asserts admin plugin visibility, PowerDNS-routed `TXT` resolution, runtime `WALLET` mapping, and authenticated audit visibility without live TON Center API credentials.
- Extended the deterministic Docker DNS integration fixture path with an enabled Tezos Domains adapter fixture. The Docker config now routes `.tez` through `tezos-domains` using the existing `tezos-domains-api` GraphQL backend contract, the fixture serves deterministic `/graphql` domain data for `alice.tez`, and the acceptance script asserts admin plugin visibility, PowerDNS-routed `TXT` resolution, runtime `WALLET` mapping, and authenticated audit visibility without live Tezos Domains API credentials.
- Extended the deterministic Docker DNS integration fixture path with an enabled Aptos Names adapter fixture. The Docker config now routes `.apt` through `aptos-names` using the existing `aptos-names-api` backend contract, the fixture serves deterministic `/api/mainnet/v3/address/alice` data, and the acceptance script asserts admin plugin visibility, PowerDNS-routed `TYPE262` posture, runtime `WALLET` mapping, and authenticated audit visibility without live Aptos Names API credentials.

## Latest Validation

Validated on 2026-06-05 13:28 CST after adding deterministic Docker Aptos Names fixture assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
```

Results:

- PASS: Docker acceptance shell syntax, Python fixture compilation, Docker integration config validation with 11 plugins / 11 routes, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `7daed50`; the working tree contains this run's validated Docker Aptos Names fixture assertions plus required ledger updates and automation-maintained context/lesson updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 12:04 CST after adding deterministic Docker Tezos Domains fixture assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
```

Results:

- PASS: Docker acceptance shell syntax, Python fixture compilation, Docker integration config validation with 10 plugins / 10 routes, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `b93e074`; the working tree contains this run's validated Docker Tezos Domains fixture assertions plus required ledger updates and automation-maintained context/lesson updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 10:49 CST after adding deterministic Docker SPACE ID fixture assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
git rev-parse --short HEAD && git status --short
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: Docker acceptance shell syntax, Python fixture compilation, Docker integration config validation with 8 plugins / 8 routes, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `39e5a04`; the working tree contains this run's validated Docker SPACE ID fixture assertions plus required ledger updates and automation-maintained context/lesson updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 10:12 CST after adding deterministic Docker PulseChain PNS JSON-RPC fixture assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
git status --short
git rev-parse --short HEAD
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: Docker acceptance shell syntax, Python fixture compilation, Docker integration config validation with 7 plugins / 7 routes, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `45cef65`; the working tree contains this run's validated Docker PulseChain fixture assertions plus required ledger updates and automation-maintained context/lesson updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 09:36 CST after adding deterministic Docker ENS JSON-RPC fixture assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
git status --short && git rev-parse --short HEAD
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: Docker acceptance shell syntax, Python fixture compilation, Docker integration config validation with 6 plugins / 6 routes, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `00e577e`; the working tree contains this run's validated Docker ENS fixture assertions plus required ledger updates and automation-maintained context/lesson updates.
- No new recurring error pattern was observed; one documentation search command hit the already-known shell backtick quoting pitfall and was not added as a new development lesson.

Validated on 2026-06-05 09:00 CST after adding deterministic Docker PNS-Polkadot fixture assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
git status --short && git rev-parse --short HEAD
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: Docker acceptance shell syntax, Python fixture compilation, Docker integration config validation with 5 plugins / 5 routes, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `8cff242`; the working tree contains this run's validated Docker PNS-Polkadot fixture assertions plus required ledger updates and automation-maintained context/lesson updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 08:23 CST after adding deterministic Docker Stacks BNS fixture assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
git status --short
git rev-parse --short HEAD
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: Docker acceptance shell syntax, Python fixture compilation, Docker integration config validation, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `546a62f`; the working tree contains this run's validated Docker Stacks BNS fixture assertions plus required ledger updates and automation-maintained context/lesson updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 06:46 CST after adding deterministic Docker Unstoppable Domains fixture assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
git status --short
git rev-parse --short HEAD
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: Docker acceptance shell syntax, Python fixture compilation, Docker integration config validation, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `65a389b`; the working tree contains this run's validated Docker Unstoppable fixture assertions plus required ledger updates and automation-maintained context/lesson updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 05:14 CST after adding Docker DNS rebinding fixture assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
git status --short
git rev-parse --short HEAD
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: Docker acceptance shell syntax, Python fixture compilation, Docker integration config validation, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `8b7feb7`; the working tree contains this run's validated Docker rebinding fixture assertion, required ledger updates, and automation-maintained context/lesson updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 04:33 CST after adding Docker integration audit time-window assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: Docker acceptance shell syntax, Docker integration config validation, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `f464666`; the working tree contains this run's Docker audit time-window assertion and required ledger updates plus automation-maintained context/lesson files.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 03:57 CST after adding audit event `since` / `until` time-window filters:

```bash
gofmt -w internal/dnslog/dnslog.go internal/dnslog/dnslog_test.go internal/httpapi/httpapi.go internal/httpapi/httpapi_test.go cmd/anyns-admin-api/main_test.go cmd/anyns-plugin-runtime/main_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/dnslog ./internal/httpapi ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: `gofmt`, targeted audit filter tests, broad Go tests, broad Go vet, and service builds.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because the Docker daemon is unavailable in this session.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `5fd9e35`; the working tree contains this run's validated audit time-window filter changes, required ledger updates, and generated context/lesson updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 03:22 CST after adding Docker integration audit-summary assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
git status --short
git rev-parse --short HEAD
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: Docker acceptance shell syntax, fixture Python syntax, Docker integration config validation, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because `docker info` reports the Docker daemon is unavailable in this session.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted once after validation and failed because `.git/index.lock` could not be created on a read-only filesystem. Latest committed hash remains `83515bc`; the working tree contains this run's validated Docker audit-summary assertions, required ledger updates, and generated context/lesson updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-05 00:30 CST after adding the Docker log-forwarder service and DNSLog/honeypot assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: Docker acceptance shell syntax, targeted log-forwarder package check, Docker integration config validation, Docker Compose rendering, broad Go tests, broad Go vet, and service builds.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because `docker info` reports the Docker daemon is unavailable in this session.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted after validation but failed because `.git/index.lock` could not be created on a read-only filesystem. The latest committed hash remains `9ac58de`, and the working tree contains the validated Docker log-forwarder integration coverage plus ledger updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-04 23:55 CST after adding the Docker admin API service and security denylist/sinkhole assertions:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
docker compose -f tests/docker/compose.dns-integration.yml config
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- PASS: shell syntax, Docker Compose rendering, Docker integration config validation, fixture Python syntax, broad Go tests, broad Go vet, and service builds.
- PASS with documented SKIP: `tests/acceptance/check-local.sh` completed while runtime socket smoke skipped because `listen tcp 127.0.0.1:18081` is denied in this sandbox.
- SKIP: `tests/acceptance/docker-dns-integration.sh` runtime execution because `docker info` reports the Docker daemon is unavailable in this session.
- Git commit was attempted after validation but failed because `.git/index.lock` could not be created on a read-only filesystem. The latest committed hash remains `401bd60`, and the working tree contains the validated Docker admin/security assertion and ledger updates.
- No new recurring error pattern was observed; `DEVELOPMENT_LESSONS.md` did not need a manual rule update.

Validated on 2026-06-04 23:18 CST after extending Docker integration assertions for `WALLET` / `TYPE262` and honeypot failed-queue metrics:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Docker acceptance shell syntax, fixture Python syntax, integration config validation, and Compose rendering passed.
- Docker runtime execution skipped because the Docker daemon is not available in this environment: `SKIP: docker daemon is not available`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP: `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- No Go files changed, so no `gofmt` was needed.
- Git commit was attempted after validation but failed because `.git/index.lock` could not be created on a read-only filesystem. The latest committed hash remains `e9d1e58`, and the working tree contains the validated Docker assertion and ledger updates.

Validated on 2026-06-04 22:42 CST after adding deterministic Docker backend fixtures:

```bash
bash -n tests/acceptance/docker-dns-integration.sh
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json
docker compose -f tests/docker/compose.dns-integration.yml config
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Docker fixture script syntax, Docker acceptance shell syntax, integration config validation, and Compose rendering passed.
- Docker runtime execution skipped because the Docker daemon is not available in this environment: `SKIP: docker daemon is not available`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP: `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Git commit was attempted after validation but failed because `.git/index.lock` could not be created on a read-only filesystem. The latest committed hash remains `042261c`, and the working tree contains the validated Docker fixture changes.

Validated on 2026-06-04 08:30 CST:

```bash
gofmt -w internal/dnslog/dnslog.go internal/dnslog/dnslog_test.go internal/httpapi/httpapi.go cmd/anyns-admin-api/main.go cmd/anyns-admin-api/main_test.go cmd/anyns-plugin-runtime/main.go cmd/anyns-plugin-runtime/main_test.go cmd/anyns-log-forwarder/main.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/dnslog ./internal/httpapi ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/dnslog`, `internal/httpapi`, `cmd/anyns-admin-api`, `cmd/anyns-plugin-runtime`, and `cmd/anyns-log-forwarder` checks passed after adding audit event filters.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- `git status --short` was not run because `CODEX_RUN_CONTEXT.md` still records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-03 15:25 CST:

```bash
gofmt -w internal/httpapi/httpapi.go internal/httpapi/httpapi_test.go cmd/anyns-plugin-runtime/main.go cmd/anyns-plugin-runtime/main_test.go cmd/anyns-admin-api/main.go cmd/anyns-admin-api/main_test.go cmd/anyns-log-forwarder/main.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/httpapi
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-admin-api
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-plugin-runtime
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/httpapi` tests passed after adding bounded query integer parsing coverage.
- Targeted `cmd/anyns-admin-api` and `cmd/anyns-plugin-runtime` tests passed after adding no-socket audit event `limit` handler coverage.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- `git status --short` was not run because `CODEX_RUN_CONTEXT.md` still records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-03 15:10 CST:

```bash
gofmt -w internal/pdnshook/lua_contract_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/pdnshook
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/pdns-lua-hook.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/pdnshook` tests passed after adding Lua hook contract coverage for runtime security `403` / `429` result-body handling.
- `tests/acceptance/pdns-lua-hook.sh` passed without requiring a listening socket.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- `git status --short` was not run because `CODEX_RUN_CONTEXT.md` still records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-03 14:54 CST:

```bash
gofmt -w internal/pdnshook/lua_contract_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/pdnshook
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/pdns-lua-hook.sh
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/pdnshook` tests passed after adding Lua hook contract coverage for normalized runtime RR type and RCODE handling.
- `tests/acceptance/pdns-lua-hook.sh` passed without requiring a listening socket.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- One first targeted `internal/pdnshook` run failed because existing contract assertions still looked for the pre-normalization Lua snippets (`result.rcode == "NOERROR"` and direct `rr.type` wallet checks). The assertions were updated to the normalized `rcode` / `rr_name` contract and the targeted package passed before broad validation.
- `git status --short` was not run because `CODEX_RUN_CONTEXT.md` still records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-03 14:11 CST:

```bash
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/config
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/plugins/wave1` tests passed after adding the opt-in Freename Resolution API adapter and no-socket request/response coverage.
- Targeted `internal/config` tests passed after accepting `freename-resolution-api` only for the `freename-fns` plugin.
- `anyns-config-check` passed for `configs/anyns/config.example.json`; it reports `plugins: 19` and `routes: 19`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- `git status --short` was not run because `CODEX_RUN_CONTEXT.md` still records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-03 13:57 CST:

```bash
gofmt -w internal/dnslog/dnslog.go internal/dnslog/dnslog_test.go internal/observability/metrics.go internal/observability/metrics_test.go cmd/anyns-plugin-runtime/main_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/dnslog
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/observability
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-plugin-runtime
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/dnslog` tests passed after adding retained DNSLog latency aggregation overall and by source plugin.
- Targeted `internal/observability` tests passed after adding Prometheus gauges for retained overall latency and source-plugin latency.
- Targeted `cmd/anyns-plugin-runtime` tests passed after extending the no-socket runtime `/metrics` and `/api/v1/audit/summary` contract checks for latency observability.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- `git status --short` was not run because `CODEX_RUN_CONTEXT.md` still records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-03 13:35 CST:

```bash
gofmt -w internal/honeypot/client.go internal/honeypot/client_test.go internal/observability/metrics.go internal/observability/metrics_test.go cmd/anyns-admin-api/main.go cmd/anyns-log-forwarder/main.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/honeypot
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/observability
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/honeypot` tests passed after adding cumulative replay-retained and replay-dropped counters to `DeliveryStatus`.
- Targeted `internal/observability` tests passed after adding Prometheus counters for replay-retained and replay-dropped honeypot batches.
- Targeted `cmd/anyns-admin-api` / `cmd/anyns-log-forwarder` validation passed; log forwarder has no package tests, and both command packages compile under the targeted test command.
- Broad `go test`, `go vet`, and service `go build` passed after a final targeted honeypot rerun.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- One final documentation readback `rg` failed due a shell backtick in the search pattern; it was rerun without shell-special backticks and passed. No code validation failed.
- `git status --short` was not run because `CODEX_RUN_CONTEXT.md` still records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-03 12:38 CST:

```bash
gofmt -w internal/dnslog/dnslog.go internal/dnslog/dnslog_test.go internal/observability/metrics.go internal/observability/metrics_test.go cmd/anyns-plugin-runtime/main_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/dnslog
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/observability
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-plugin-runtime
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/dnslog` tests passed after adding `Summary.ByRCode` aggregation.
- Targeted `internal/observability` tests passed after adding `anyns_dnslog_events_by_rcode` to the shared Prometheus writer.
- Targeted `cmd/anyns-plugin-runtime` tests passed after extending the runtime `/metrics` and `/api/v1/audit/summary` contract checks for RCODE distribution. One first targeted runtime run failed because the new assertion expected `NOERROR`, while the existing high-entropy HNS fixture correctly returns routed `NXDOMAIN`; the expectation was corrected to `NXDOMAIN` and the targeted package passed before broad validation.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-03 12:32 CST:

```bash
gofmt -w internal/observability/metrics.go internal/observability/metrics_test.go cmd/anyns-plugin-runtime/main_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/observability
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-plugin-runtime
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/observability` tests passed after adding Prometheus metrics for DNSLog source-plugin counts and top qname counts.
- Targeted `cmd/anyns-plugin-runtime` tests passed, confirming the runtime `/metrics` handler exposes the new plugin and qname metrics after a PowerDNS/runtime-style resolve path.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-02 08:31 CST:

```bash
gofmt -w internal/plugins/router.go internal/plugins/router_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-plugin-runtime
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/plugins` tests passed after adding normalized `client_view` / `tenant` route matching and cache-key coverage.
- Targeted `cmd/anyns-plugin-runtime` tests passed, confirming the runtime handler path still works with the router change.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed, with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Runtime socket acceptance was skipped because the environment still denies listening sockets. No Docker or direct socket retry was attempted beyond the acceptance script's documented SKIP path.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-02 07:55 CST:

```bash
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/config
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/config` tests passed after accepting `ada-handle-api` only for the `ada-handle` plugin.
- Targeted `internal/plugins/wave1` tests passed after adding the opt-in ADA Handle public API adapter and no-socket request/response coverage. One first targeted run failed because the no-record test used a payload containing `handle`, which is intentionally mapped to `TXT`; the fixture was narrowed to `{}` and the targeted package passed before broad validation.
- `anyns-config-check` passed for `configs/anyns/config.example.json`; it reports `plugins: 19` and `routes: 19`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed, with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Runtime socket acceptance was skipped because the environment still denies listening sockets. No Docker or direct socket retry was attempted beyond the acceptance script's documented SKIP path.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-02 07:16 CST:

```bash
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/config
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/plugins/wave1` tests passed after adding the opt-in OpenAlias DNS TXT adapter and no-socket request/response coverage.
- Targeted `internal/config` tests passed after accepting `openalias-dns-txt` only for the `openalias` plugin.
- `anyns-config-check` passed for `configs/anyns/config.example.json`; it reports `plugins: 19` and `routes: 19`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed, with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Runtime socket acceptance was skipped because the environment still denies listening sockets. No Docker or direct socket retry was attempted beyond the acceptance script's documented SKIP path.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-02 06:39 CST:

```bash
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/config
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/plugins/wave1` tests passed after adding the opt-in RIF/RNS JSON-RPC adapter and no-socket request/response coverage.
- Targeted `internal/config` tests passed after accepting `rif-rns-json-rpc` only for the `rif-rns` plugin.
- `anyns-config-check` passed for `configs/anyns/config.example.json`; it reports `plugins: 19` and `routes: 19`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed, with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Runtime socket acceptance was skipped because the environment still denies listening sockets. No Docker or socket retry was attempted beyond the acceptance script's documented SKIP path.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Validated on 2026-06-02 06:03 CST:

```bash
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/config
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/plugins/wave1` tests passed after adding the opt-in FIO Chain API adapter and no-socket request/response coverage.
- Targeted `internal/config` tests passed after accepting `fio-chain-api` only for the `fio-handle` plugin.
- `anyns-config-check` passed for `configs/anyns/config.example.json`; it reports `plugins: 19` and `routes: 19`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed, with the expected runtime socket smoke SKIP in this sandbox: `anyns-plugin-runtime exited before listening on 127.0.0.1:18081`; runtime log detail was `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Runtime socket acceptance was skipped because the environment still denies listening sockets. No Docker or socket retry was attempted beyond the acceptance script's documented SKIP path.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Previous validation on 2026-06-02 05:26 CST:

```bash
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/router.go internal/plugins/router_test.go internal/config/config.go internal/config/config_test.go internal/app/app_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/config
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins ./internal/app ./internal/plugins/wave1
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
date '+%Y-%m-%d %H:%M %Z'
```

Results:

- Targeted `internal/config` tests passed after adding Wave 3 runtime-json skeleton validation.
- Targeted `internal/plugins`, `internal/app`, and `internal/plugins/wave1` tests passed after registering Wave 3 skeletons and adding the `.bit` route-priority regression test.
- `anyns-config-check` passed for `configs/anyns/config.example.json`; it reports `plugins: 19` and `routes: 19`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed, with the expected runtime socket smoke SKIP in this sandbox: `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Runtime socket acceptance was skipped because the environment still denies listening sockets. No Docker or socket retry was attempted beyond the acceptance script's documented SKIP path.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Previous validation on 2026-06-02 04:13 CST:

```bash
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1 ./internal/config
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/app ./internal/config ./internal/plugins/wave1 ./internal/plugins
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
```

Results:

- Targeted `internal/plugins/wave1` and `internal/config` tests passed after adding the opt-in TON Center v3 DNS records adapter and backend type config validation.
- Targeted `internal/app`, `internal/config`, `internal/plugins/wave1`, and `internal/plugins` tests passed after the sample config was updated to demonstrate `toncenter-v3-dns`.
- `anyns-config-check` passed for `configs/anyns/config.example.json`; it reports `plugins: 13` and `routes: 13`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed, with the expected runtime socket smoke SKIP in this sandbox: `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Runtime socket acceptance was skipped because the environment still denies listening sockets. No Docker or socket retry was attempted beyond the acceptance script's documented SKIP path.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Previous validation on 2026-06-02 03:37 CST:

```bash
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1 ./internal/config
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/app ./internal/config ./internal/plugins/wave1 ./internal/plugins
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
```

Results:

- Targeted `internal/plugins/wave1` and `internal/config` tests passed after adding the opt-in Solana SNS QuickNode JSON-RPC adapter and backend type config validation.
- Targeted `internal/app`, `internal/config`, `internal/plugins/wave1`, and `internal/plugins` tests passed after the sample config was updated to demonstrate `solana-sns-quicknode`.
- `anyns-config-check` passed for `configs/anyns/config.example.json`; it reports `plugins: 13` and `routes: 13`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed, with the expected runtime socket smoke SKIP in this sandbox: `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Runtime socket acceptance was skipped because the environment still denies listening sockets. No Docker or socket retry was attempted beyond the acceptance script's documented SKIP path.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Previous validation on 2026-06-02 02:24 CST:

```bash
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1 ./internal/config
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/app ./internal/config ./internal/plugins/wave1 ./internal/plugins
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
```

Results:

- Targeted `internal/plugins/wave1` and `internal/config` tests passed after adding the opt-in Tezos Domains GraphQL API adapter and backend type config validation.
- Targeted `internal/app`, `internal/config`, `internal/plugins/wave1`, and `internal/plugins` tests passed after the sample config was updated to demonstrate `tezos-domains-api`.
- `anyns-config-check` passed for `configs/anyns/config.example.json`; it reports `plugins: 13` and `routes: 13`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed, with the expected runtime socket smoke SKIP in this sandbox: `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Runtime socket acceptance was skipped because the environment still denies listening sockets. No Docker or socket retry was attempted beyond the acceptance script's documented SKIP path.
- `git status --short` was not rerun because `CODEX_RUN_CONTEXT.md` already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

Previous validation on 2026-06-02 02:13 CST:

```bash
gofmt -w internal/plugins/wave1/plugin.go internal/config/config.go internal/plugins/router.go internal/app/app_test.go internal/config/config_test.go
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/app ./internal/config ./internal/plugins/wave1 ./internal/plugins
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh
```

Results:

- Targeted `internal/app`, `internal/config`, `internal/plugins/wave1`, and `internal/plugins` tests passed after adding disabled-by-default Wave 2 runtime-json skeletons and routes.
- `anyns-config-check` passed for `configs/anyns/config.example.json`; it reported `plugins: 13` and `routes: 13`.
- Broad `go test`, `go vet`, and service `go build` passed.
- `tests/acceptance/check-local.sh` passed, with the expected runtime socket smoke SKIP in this sandbox: `listen tcp 127.0.0.1:18081: socket: operation not permitted`.
- Runtime socket acceptance was skipped in this execution environment because the sandbox rejected listening sockets: `listen tcp 127.0.0.1:18081: socket: operation not permitted`. The script records this reason and continues with no-socket validation.
- `git status --short` was not rerun because the current run context already records the known repository metadata issue: `fatal: not a git repository (or any of the parent directories): .git`.

## Run Commands

Local validation:

```bash
export GOCACHE=/tmp/anyns-go-build
go test -buildvcs=false ./...
go vet -buildvcs=false ./...
go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check ./cmd/anyns-management-key
```

Local bootstrap:

```bash
./scripts/bootstrap-local.sh
```

Docker Compose:

```bash
cp .env.example .env
docker compose --env-file .env up --build
```

Config file:

```bash
export ANYNS_CONFIG_FILE=./configs/anyns/config.example.json
export ANYNS_ADMIN_PROXY_RUNTIME_CONTROL=true
export ANYNS_RUNTIME_CONTROL_URL=http://127.0.0.1:8081
```

Runtime HNS sample:

```bash
curl -s http://127.0.0.1:8081/api/v1/resolve \
  -H 'Content-Type: application/json' \
  -d '{"qname":"example.hns","qtype":"A","context":{"trace_id":"manual-hns","client_ip":"127.0.0.1","client_view":"default","tenant":"default"}}'
```

Admin API samples:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/api/v1/plugins
curl -X POST http://127.0.0.1:8080/api/v1/plugins/hns/disable
curl -X POST http://127.0.0.1:8080/api/v1/plugins/hns/enable
curl -X POST http://127.0.0.1:8080/api/v1/cache/flush
curl http://127.0.0.1:8080/api/v1/control-plane/boundary
curl -X POST http://127.0.0.1:8080/api/v1/policies/reload
curl http://127.0.0.1:8080/api/v1/honeypot/status
curl -X POST 'http://127.0.0.1:8080/api/v1/honeypot/drain?limit=10'

# If management.auth_required is enabled:
curl -H 'Authorization: Bearer <api-key>' http://127.0.0.1:8080/api/v1/plugins
```

Management key lifecycle CLI:

```bash
go run -buildvcs=false ./cmd/anyns-management-key generate \
  --config configs/anyns/config.example.json \
  --id ops-read-successor \
  --role ops-reader \
  --not-before 2026-06-01T00:00:00Z \
  --expires-at 2026-09-01T00:00:00Z

go run -buildvcs=false ./cmd/anyns-management-key revoke \
  --config configs/anyns/config.example.json \
  --id ops-read

go run -buildvcs=false ./cmd/anyns-management-key rotate \
  --config configs/anyns/config.example.json \
  --id ops-read \
  --new-id ops-read-next \
  --not-before 2026-06-01T00:00:00Z \
  --valid-for 2160h \
  --reload-url http://127.0.0.1:8080 \
  --reload-url http://127.0.0.1:8081
```

Runtime control samples:

```bash
curl http://127.0.0.1:8081/api/v1/plugins
curl -X POST http://127.0.0.1:8081/api/v1/plugins/hns/disable
curl -X POST http://127.0.0.1:8081/api/v1/plugins/hns/enable
curl -X POST http://127.0.0.1:8081/api/v1/cache/flush
curl http://127.0.0.1:8081/api/v1/control-plane/boundary
curl -X POST http://127.0.0.1:8081/api/v1/policies/reload
```

Acceptance script after runtime is listening:

```bash
ANYNS_RUNTIME_URL=http://127.0.0.1:8081 ./tests/acceptance/hns-resolve.sh
```

Local non-socket acceptance checks:

```bash
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh
```

## Verification Results

Completed in this environment:

```text
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1 ./internal/config   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/app ./internal/config ./internal/plugins/wave1 ./internal/plugins   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

Latest pass on 2026-06-01 after adding the opt-in ENS JSON-RPC backend adapter:

```text
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1 ./internal/config   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

Latest pass on 2026-06-01 after adding repeated management-key CLI reload targets:

```text
gofmt -w cmd/anyns-management-key/main.go cmd/anyns-management-key/main_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-management-key   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

Latest pass on 2026-06-01 after adding file-backed secret references:

```text
gofmt -w internal/config/config.go internal/config/config_test.go cmd/anyns-management-key/main.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/config ./cmd/anyns-management-key   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

Latest pass on 2026-06-01 after adding the opt-in Namecoin `.bit` JSON-RPC backend adapter:

```text
gofmt -w internal/config/config.go internal/config/config_test.go internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/app/app.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1 ./internal/config ./internal/app   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

Latest pass on 2026-06-01 after adding the opt-in Unstoppable Domains Resolution Service backend adapter:

```text
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1 ./internal/config   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

Latest pass on 2026-06-01 after adding the opt-in Stacks BNS API backend adapter:

```text
gofmt -w internal/plugins/wave1/plugin.go internal/plugins/wave1/plugin_test.go internal/config/config.go internal/config/config_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/wave1 ./internal/config   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

Latest pass on 2026-06-01 after runtime security-block enforcement:

```text
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh   PASS
```

Latest pass on 2026-06-01 after adding configurable HNS remote backend support:

```text
gofmt -w internal/plugins/hns/plugin.go internal/plugins/hns/plugin_test.go internal/app/app.go internal/app/app_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh   PASS
```

Latest pass on 2026-06-01 after adding no-socket config validation and the `anyns-config-check` acceptance gate:

```text
gofmt -w internal/config/config.go internal/config/config_test.go cmd/anyns-config-check/main.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check   PASS
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh   PASS
```

Latest pass on 2026-06-01 after tightening PowerDNS Lua hook runtime rcode handling:

```text
gofmt -w internal/pdnshook/lua_contract_test.go cmd/anyns-plugin-runtime/main_test.go   PASS
bash tests/acceptance/pdns-lua-hook.sh   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/pdnshook ./cmd/anyns-plugin-runtime   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check   PASS
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh   PASS
```

Latest pass on 2026-06-01 after adding configurable security allowlist/denylist/sinkhole enforcement:

```text
gofmt -w internal/security/analyzer.go internal/security/analyzer_test.go internal/config/config.go internal/config/config_test.go cmd/anyns-plugin-runtime/main.go cmd/anyns-plugin-runtime/main_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check   PASS
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh   PASS
```

Latest pass on 2026-06-01 after adding DNSLog audit summaries and expanded Prometheus DNSLog/security metrics:

```text
gofmt -w internal/dnslog/dnslog.go internal/dnslog/dnslog_test.go internal/observability/metrics.go internal/observability/metrics_test.go cmd/anyns-admin-api/main.go cmd/anyns-admin-api/main_test.go cmd/anyns-plugin-runtime/main.go cmd/anyns-plugin-runtime/main_test.go cmd/anyns-log-forwarder/main.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check   PASS
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh   PASS
bash tests/acceptance/pdns-lua-hook.sh   PASS
```

Latest pass on 2026-06-01 after enforcing config validation on service startup and hot reload:

```text
gofmt -w cmd/anyns-admin-api/main.go cmd/anyns-admin-api/main_test.go cmd/anyns-plugin-runtime/main.go cmd/anyns-plugin-runtime/main_test.go cmd/anyns-log-forwarder/main.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check   PASS
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh   PASS
bash tests/acceptance/pdns-lua-hook.sh   PASS
```

Latest pass on 2026-06-01 after adding direct HNS `dns://` resolver backend support:

```text
gofmt -w internal/plugins/hns/plugin.go internal/plugins/hns/dns_backend.go internal/plugins/hns/plugin_test.go internal/config/config.go internal/config/config_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/hns ./internal/config   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check   PASS
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh   PASS
```

Latest pass on 2026-06-01 after adding query-rate and random-subdomain rate-limit enforcement:

```text
gofmt -w internal/security/analyzer.go internal/security/analyzer_test.go internal/config/config.go internal/config/config_test.go cmd/anyns-plugin-runtime/main.go cmd/anyns-plugin-runtime/main_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/security ./internal/config ./cmd/anyns-plugin-runtime   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check   PASS
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh   PASS
```

Latest pass on 2026-06-01 after adding HNS `dns://` UDP truncation fallback to DNS-over-TCP and extending the PowerDNS Lua hook RR mapping:

```text
gofmt -w internal/pdnshook/lua_contract_test.go internal/plugins/hns/plugin.go internal/plugins/hns/dns_backend.go internal/plugins/hns/plugin_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder ./cmd/anyns-config-check   PASS
GOCACHE=/tmp/anyns-go-build ./tests/acceptance/check-local.sh   PASS
```

Latest pass on 2026-06-01 after adding read-scoped management key rotation observability:

```text
gofmt -w internal/controlplane/controlplane.go internal/controlplane/controlplane_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/controlplane   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...    PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS
```

Latest pass on 2026-06-01 after adding management key client CIDR restrictions:

```text
gofmt -w internal/config/config.go internal/config/config_test.go internal/httpapi/httpapi.go internal/httpapi/httpapi_test.go internal/controlplane/controlplane.go internal/controlplane/controlplane_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/config   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/httpapi   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/controlplane   PASS after fixing the test request RemoteAddr to match the configured allowlist
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

Latest pass on 2026-06-01 after adding fine-grained management scopes:

```text
gofmt -w internal/httpapi/httpapi.go internal/httpapi/httpapi_test.go internal/controlplane/controlplane.go internal/controlplane/controlplane_test.go internal/config/config.go internal/config/config_test.go cmd/anyns-admin-api/main.go cmd/anyns-plugin-runtime/main.go cmd/anyns-log-forwarder/main.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/httpapi   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/controlplane   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/config   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-admin-api   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-plugin-runtime   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./cmd/anyns-log-forwarder   PASS (no test files)
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

Latest pass on 2026-06-01 after adding management RBAC role templates:

```text
gofmt -w internal/config/config.go internal/config/config_test.go internal/httpapi/httpapi.go internal/httpapi/httpapi_test.go internal/controlplane/controlplane.go internal/controlplane/controlplane_test.go cmd/anyns-config-check/main.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/config   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/httpapi   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/controlplane   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check configs/anyns/config.example.json   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

New or expanded tests recorded across recent passes:

```text
internal/observability: TestWritePrometheusTextIncludesDNSLogAndHoneypotState (expanded source-plugin and top qname metrics coverage)
cmd/anyns-plugin-runtime: TestResolveEndpointPersistsDNSLogAndQueuesHoneypotFailure (expanded runtime `/metrics` source-plugin and top qname coverage)
internal/plugins/wave1: TestRemoteBackendResolveUsesJSONContract
internal/plugins/wave1: TestRemoteBackendStatusFailureReturnsServFail
internal/plugins/wave1: TestRemoteBackendAcceptsDirectResolveResult
internal/plugins/wave1: TestOpenAliasDNSTXTBackendMapsRecords
internal/plugins/wave1: TestOpenAliasDNSTXTBackendNoRecordReturnsNXDomain
internal/plugins/wave1: TestOpenAliasDNSTXTBackendErrorReturnsServFail
internal/config: TestValidateAcceptsOpenAliasDNSTXTBackendType
internal/config: TestLoadAppliesFileConfigAndDefaults (expanded plugin backend config coverage)
internal/app: TestNewFromConfigAppliesWave1BackendConfig
cmd/anyns-admin-api: TestPoliciesReloadAppliesConfigToProcessState
cmd/anyns-admin-api: TestPoliciesReloadRequiresConfigFile
cmd/anyns-admin-api: TestPoliciesReloadUpdatesControlPlaneConfig
cmd/anyns-plugin-runtime: TestRuntimePoliciesReloadAppliesConfigToLiveDataPlane
cmd/anyns-plugin-runtime: TestResolveEndpointBlocksRebindingResponse
cmd/anyns-plugin-runtime: TestResolveEndpointQueryBlockUsesResolveResultContract
internal/controlplane: TestControlPlaneWritesManagementAuditForMutation
internal/plugins/hns: TestRemoteBackendResolveUsesRuntimeJSONContract
internal/plugins/hns: TestRemoteBackendStatusFailureReturnsServFail
internal/app: TestNewFromConfigAppliesHNSBackendConfig
internal/config: TestValidateAcceptsExampleConfig
internal/config: TestValidateRejectsInvalidIntegrationConfig
cmd/anyns-plugin-runtime: TestResolveEndpointReturnsRoutedNXDomainForMissingHNS
internal/pdnshook: TestRecursorLuaHookSuppressesICANNFallbackForRuntimeRcodes
internal/security: TestAnalyzeQueryHonorsListPolicies
internal/security: TestAnalyzeQueryRateLimitsClientWindow
internal/security: TestAnalyzeQueryRateLimitsRandomSubdomains
cmd/anyns-plugin-runtime: TestResolveEndpointDenylistBlockUsesResolveResultContract
cmd/anyns-plugin-runtime: TestResolveEndpointSinkholeReturnsConfiguredAnswer
cmd/anyns-plugin-runtime: TestResolveEndpointRateLimitUsesResolveResultContract
internal/dnslog: TestStoreSummaryAggregatesSecurityAndTopValues
internal/observability: TestWritePrometheusTextIncludesDNSLogAndHoneypotState (expanded DNSLog/security metrics coverage)
cmd/anyns-admin-api: TestAuditSummaryEndpointAggregatesDNSLog
cmd/anyns-admin-api: TestPoliciesReloadRejectsInvalidConfig
cmd/anyns-plugin-runtime: TestResolveEndpointPersistsDNSLogAndQueuesHoneypotFailure (expanded runtime audit summary and metrics coverage)
cmd/anyns-plugin-runtime: TestRuntimePoliciesReloadRejectsInvalidConfig
internal/plugins/hns: TestDNSBackendAddressDefaultsPort
internal/plugins/hns: TestParseDNSResponseMapsHNSDNSAnswers
internal/plugins/hns: TestParseDNSResponseMapsNXDomain
internal/plugins/hns: TestDNSBackendFallsBackToTCPOnTruncatedUDP
internal/pdnshook: TestRecursorLuaHookRuntimeContract (expanded DS/TLSA/SVCB/HTTPS mapping coverage)
internal/controlplane: TestManagementKeysEndpointReportsRotationStatusWithoutSecrets
internal/httpapi: TestPrincipalFromRequestHonorsManagementKeyClientCIDRs
internal/config: TestLoadAppliesFileConfigAndDefaults (expanded management key CIDR config coverage)
internal/config: TestValidateRejectsInvalidIntegrationConfig (expanded invalid management key CIDR validation coverage)
internal/httpapi: TestPrincipalHasFineGrainedManagementScopes
internal/controlplane: TestControlPlaneHonorsFineGrainedScopes
internal/config: TestValidateAcceptsFineGrainedManagementScopes
internal/config: TestManagementScopesForKeyExpandsRoleTemplates
internal/httpapi: TestPrincipalFromRequestExpandsManagementRoles
internal/controlplane: TestManagementKeysEndpointReportsRotationStatusWithoutSecrets (expanded role-template metadata coverage)
internal/config: TestValidateAcceptsFineGrainedManagementScopes (expanded revoked_at validation coverage)
internal/httpapi: TestPrincipalFromRequestHonorsManagementKeyRotationWindow (expanded revoked key rejection coverage)
internal/controlplane: TestManagementKeysEndpointReportsRotationStatusWithoutSecrets (expanded revoked key redaction/status coverage)
internal/controlplane: TestManagementKeysEndpointReportsLifecycleActions (expanded revoked key lifecycle action coverage)
cmd/anyns-management-key: TestGenerateAddsManagementKeyAndPrintsTokenOnce
cmd/anyns-management-key: TestRevokeMarksManagementKeyWithoutRemovingAuditMetadata
cmd/anyns-management-key: TestGenerateRejectsDuplicateManagementKeyID
cmd/anyns-management-key: TestStatusFetchesManagementKeyLifecyclePlan
cmd/anyns-management-key: TestStatusSurfacesEndpointFailure
cmd/anyns-management-key: TestRotateAddsSuccessorWithCopiedAuthorizationMetadata
cmd/anyns-management-key: TestRotateLiveGuardRejectsExistingSuccessor
cmd/anyns-management-key: TestGenerateReloadsMultipleControlPlanes
internal/config: TestLoadFileResolvesSecretFileReferences
internal/plugins/wave1: TestNamecoinJSONRPCBackendMapsRecords
internal/plugins/wave1: TestNamecoinJSONRPCBackendNameNotFoundReturnsNXDomain
internal/plugins/wave1: TestUnstoppableResolutionAPIBackendMapsRecords
internal/plugins/wave1: TestUnstoppableResolutionAPIBackendNotFoundReturnsNXDomain
internal/config: TestValidateAcceptsUnstoppableResolutionBackendType
internal/plugins/wave1: TestStacksBNSAPIBackendMapsLegacyZonefile
internal/plugins/wave1: TestStacksBNSAPIBackendMapsJSONZonefile
internal/plugins/wave1: TestStacksBNSAPIBackendNotFoundReturnsNXDomain
internal/config: TestValidateAcceptsStacksBNSBackendType
internal/plugins/wave1: TestENSJSONRPCBackendMapsWalletTextAndContenthash
internal/plugins/wave1: TestENSJSONRPCBackendNoResolverReturnsNXDomain
internal/plugins/wave1: TestENSNamehashUsesLegacyKeccak
internal/config: TestValidateAcceptsENSJSONRPCBackendType
```

Latest pass on 2026-06-04 after adding expanded exact-match audit event filters:

```text
gofmt -w internal/dnslog/dnslog.go internal/dnslog/dnslog_test.go internal/httpapi/httpapi.go internal/httpapi/httpapi_test.go cmd/anyns-admin-api/main_test.go cmd/anyns-plugin-runtime/main_test.go   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/dnslog ./internal/httpapi ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

Latest pass on 2026-06-05 after requiring management auth in the deterministic Docker DNS fixture stack:

```text
bash -n tests/acceptance/docker-dns-integration.sh   PASS
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json   PASS; output reported management_auth:true, management_keys:1, management_roles:1, plugins:2, and routes:2
docker compose -f tests/docker/compose.dns-integration.yml config   PASS; rendered 151 lines
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh   SKIP; Docker daemon is not available
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

New Docker integration coverage added in this pass:

```text
tests/docker/anyns-config.json now enables management.auth_required with an integration-only scoped management key.
tests/acceptance/docker-dns-integration.sh now asserts unauthenticated 401 responses and authorized Bearer-token access for admin boundary/management-key/plugin reads, runtime audit reads, and log-forwarder audit/honeypot status reads.
The management-key response assertion checks that the token material is not exposed.
```

Latest pass on 2026-06-05 after adding Docker policy reload assertions:

```text
bash -n tests/acceptance/docker-dns-integration.sh   PASS
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json   PASS; output reported management_auth:true, management_keys:2, management_roles:2, plugins:2, and routes:2
docker compose -f tests/docker/compose.dns-integration.yml config   PASS
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh   SKIP; Docker daemon is not available
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

New Docker integration coverage added in this pass:

```text
tests/docker/anyns-config.json now includes a separate integration-only policy writer role/key.
tests/acceptance/docker-dns-integration.sh now asserts unauthenticated 401, read-token 403, successful policy-writer reload, and management audit visibility for both admin API and plugin runtime policy reload endpoints.
Policy writer token material is also checked as absent from management-key metadata.
```

Additional check-local note from this environment:

```text
docker compose config render passed using .env.example; root .env was created temporarily and cleaned up
luac is not installed, so Lua syntax parsing was skipped by the acceptance script
Wave 1 backend tests use a custom in-process HTTP RoundTripper and do not require listening sockets
ENS JSON-RPC adapter tests use mocked `eth_call` responses and do not require an Ethereum RPC network connection
OpenAlias DNS TXT adapter tests use a custom in-process HTTP RoundTripper and do not require live DNS or listening sockets
Management/runtime reload tests use httptest request handling and do not require listening sockets
Management mutation audit tests use httptest request handling and the DNSLog store; no listening sockets are required
Runtime security-block tests use httptest request handling and do not require listening sockets
Runtime security denylist/sinkhole tests use httptest request handling and do not require listening sockets
```

Not completed in this environment:

- HTTP acceptance run could not be executed because the sandbox denies listening sockets:

```text
listen tcp 127.0.0.1:18081: socket: operation not permitted
```

## Remaining Work

- Exercise the PowerDNS Recursor Lua hook inside a real PowerDNS container and confirm installed Lua modules (`socket.http`, `ltn12`, `cjson.safe`) in the target image; the hook falls back to ICANN recursion if they are missing.
- Run the HNS `dns://` backend against a real hsd/hnsd DNS resolver and then run end-to-end HNS resolution through PowerDNS Recursor. The separate Docker topology/config/script now exists, but live execution still needs Docker daemon access and opt-in P2P/SPV runtime.
- Confirm HNS `dns://` UDP truncation and DNS-over-TCP retry behavior against a real hsd/hnsd DNS resolver or resolver front end that can return TC=1 responses.
- Exercise honeypot background replay and exported Prometheus metrics against a real honeypot endpoint.
- Revisit a shared control-plane store only if multi-admin or multi-runtime deployments need coordinated state beyond the current deployment-default admin-to-runtime proxy mode.
- Extend production management key lifecycle automation beyond file-backed secret references only if a concrete external secret store target is selected.
- Extend the new Namecoin `.bit` JSON-RPC adapter after testing against a live Namecoin Core node, especially for additional Namecoin value shapes beyond `ip`, `ip6`, `ns`, `txt`/`info`, `alias`/`translate`, and `map` subdomains.
- Test the new Unstoppable Domains Resolution Service adapter against a live API key and real domains, then expand record mapping if real records expose additional shapes beyond `dns.*`, `browser.redirect_url`, `ipfs.*`, and `crypto.*.address`.
- Test the new Stacks BNS API adapter against a live Hiro/Stacks API and real `.btc` / `.stx` names, then expand zonefile mapping if real responses expose additional BNSv2 shapes beyond legacy zonefiles, `owner`, `name`, `bio`, `location`, `website`, `pfp`, `btc`, `addresses`, and `meta`.
- Test the new ENS JSON-RPC adapter against a live Ethereum RPC endpoint and real `.eth` names, then expand record mapping if live resolver responses require ENSIP-10 wildcard or CCIP-Read handling beyond direct resolver `addr`, `text`, and `contenthash` calls.
- Test the new PulseChain PNS JSON-RPC adapter against a live PulseChain RPC endpoint, actual PNS registry address, and real `.pls` names, then expand record mapping if live resolver responses require resolver methods beyond direct `addr`, `text`, and `contenthash` calls.
- Test the new PNS-Polkadot REST adapter against the live PNS API and real `.dot` names, then expand record mapping if live responses expose additional shapes beyond `records` maps with address, website, IPFS/contenthash, social/text, and DNS-style fields.
- Test the new SPACE ID Web3 Name API adapter against the live API and real `.bnb` / `.arb` names, then expand record mapping if live responses expose additional shapes beyond `getAddress` address resolution.
- Test the new Tezos Domains GraphQL adapter against the live API and real `.tez` names, then expand record mapping if live responses expose additional domain data shapes beyond address, owner, profile/text, URL/content, and DNS-style keys.
- Test the new Solana SNS QuickNode JSON-RPC adapter against a live QuickNode endpoint with the SNS marketplace plugin enabled and real `.sol` names, then expand record mapping if live responses expose additional record shapes beyond resolved public keys.
- Test the new TON Center v3 DNS records adapter against the live API and real `.ton` names, then expand record mapping if live responses expose additional shapes beyond wallet, site ADNL, storage Bag ID, next resolver, and NFT metadata fields.
- Test the new SuiNS JSON-RPC adapter against a live Sui fullnode and real `.sui` names, then expand record mapping if live responses expose additional shapes beyond `suix_resolveNameServiceAddress` address resolution.
- Test the new FIO Chain API adapter against a live FIO API endpoint and real FIO Handles, then expand record mapping if live responses expose multi-level addressing parameters beyond `public_address`.
- Test the new Freename Resolution API adapter against live `rslvr.freename.io` responses and real Freename domains, then expand mapping if live responses expose additional token, redirect, profile, IPFS, or DNS-style record fields beyond the currently covered shapes.
- Test the new RIF/RNS JSON-RPC adapter against a live RSK RPC endpoint, actual RNS registry address, and real `.rsk` names, then expand record mapping if live resolver responses require resolver methods beyond direct `addr`, `text`, and `contenthash` calls.
- Test the new OpenAlias DNS TXT adapter against live DNS TXT records or the selected production DNS-over-HTTP adapter, then expand parsing if real records expose additional standard or ecosystem-specific key-value fields beyond `recipient_address`, `recipient_name`, `tx_description`, `tx_amount`, `tx_payment_id`, `address_signature`, and `checksum`.
- Test the new ADA Handle public API adapter against live `api.handle.me` responses and real Handles, then expand record mapping if live responses expose additional Cardano address, personalization, or subHandle fields beyond the currently covered address/profile/image fields.
- Run the expanded Docker DNS integration fixture stack end to end once Docker daemon access is available.
- Run the new HNS `hnsd` / `dns://` Docker topology end to end with `ANYNS_RUN_DOCKER_HNSD_INTEGRATION=1` once Docker daemon access is available.
- Run the authenticated Docker DNS integration assertions, including policy reload coverage, end to end once Docker daemon access is available.

Latest pass on 2026-06-05 after adding Docker SuiNS fixture assertions:

```text
bash -n tests/acceptance/docker-dns-integration.sh   PASS
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json   PASS; output reported management_auth:true, management_keys:3, management_roles:3, plugins:12, routes:12, and admin_proxy_runtime:true
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml   PASS; rendered 151 lines
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh   SKIP; Docker daemon is not available
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

New Docker integration coverage added in this pass:

```text
tests/docker/anyns-config.json now enables `suins` with `backend_type: "suins-json-rpc"` against the deterministic backend fixture.
tests/docker/fixtures/backend-fixtures.py now serves no-secret Sui JSON-RPC `suix_resolveNameServiceAddress` responses for `alice.sui` and `missing.sui`.
tests/acceptance/docker-dns-integration.sh now asserts admin plugin visibility, PowerDNS-routed `alice.sui TYPE262` NOERROR posture, runtime `alice.sui WALLET`, and authenticated SuiNS audit visibility.
```

Git note:

```text
git add tests/acceptance/docker-dns-integration.sh tests/docker/anyns-config.json tests/docker/fixtures/backend-fixtures.py BACKEND_STORAGE_AND_DOCKER_TEST_PLAN.md IMPLEMENTATION_STATUS.md GIT_PROGRESS.md && git commit -m "test: add docker suins fixture assertions"   FAIL; Git could not create .git/index.lock because the repository metadata is read-only. Latest committed hash remains 08bed09.
```

Latest pass on 2026-06-05 after adding Docker reflection rate-limit assertions:

```text
bash -n tests/acceptance/docker-dns-integration.sh   PASS
python3 -m py_compile tests/docker/fixtures/backend-fixtures.py   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-config.json   PASS; output reported management_auth:true, management_keys:3, management_roles:3, plugins:2, and routes:2
docker compose -f tests/docker/compose.dns-integration.yml config >/tmp/anyns-docker-compose-rendered.yml && wc -l /tmp/anyns-docker-compose-rendered.yml   PASS; rendered 151 lines
ANYNS_RUN_DOCKER_DNS_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-dns-integration.sh   SKIP; Docker daemon is not available
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

New Docker integration coverage added in this pass:

```text
tests/acceptance/docker-dns-integration.sh now asserts that a runtime `ANY` query for `reflection.integration.test` returns HTTP 429 with the normal blocked `ResolveResult` contract, `SERVFAIL`, `reflection-amplification-rr`, `rate_limit`, and a matching authenticated runtime audit event.
```

Git note:

```text
git add tests/acceptance/docker-dns-integration.sh BACKEND_STORAGE_AND_DOCKER_TEST_PLAN.md IMPLEMENTATION_STATUS.md GIT_PROGRESS.md && git commit -m "test: add docker reflection rate-limit assertion"   FAIL; Git could not create .git/index.lock because the repository metadata is read-only. Latest committed hash remains 02336ab.
```

Latest pass on 2026-06-05 after adding the opt-in HNS hnsd Docker topology:

```text
gofmt -w internal/plugins/hns/dns_backend.go internal/plugins/hns/plugin_test.go   PASS
bash -n tests/acceptance/docker-hnsd-integration.sh   PASS
GOCACHE=/tmp/anyns-go-build go run -buildvcs=false ./cmd/anyns-config-check tests/docker/anyns-hnsd-config.json   PASS; output reported plugins:1, routes:1, security_enabled:true, and honeypot_url_configured:false
docker compose -f tests/docker/compose.hnsd.yml config >/tmp/anyns-hnsd-compose-rendered.yml && wc -l /tmp/anyns-hnsd-compose-rendered.yml   PASS; rendered 91 lines
ANYNS_RUN_DOCKER_HNSD_INTEGRATION=0 GOCACHE=/tmp/anyns-go-build bash tests/acceptance/docker-hnsd-integration.sh   SKIP; Docker daemon is not available
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./internal/plugins/hns   PASS
GOCACHE=/tmp/anyns-go-build go test -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go vet -buildvcs=false ./...   PASS
GOCACHE=/tmp/anyns-go-build go build -buildvcs=false ./cmd/anyns-admin-api ./cmd/anyns-plugin-runtime ./cmd/anyns-log-forwarder   PASS
GOCACHE=/tmp/anyns-go-build bash tests/acceptance/check-local.sh   PASS with runtime socket smoke SKIP: listen tcp 127.0.0.1:18081: socket: operation not permitted
```

New HNS live-backend preparation in this pass:

```text
The HNS dns:// backend now strips the anyNS routing suffix .hns/.hsd before querying hnsd-style alternate-root DNS resolvers, restores returned RR owner names to the original routed qname, and records raw_record.backend_query_name for audit/debugging.
tests/docker/anyns-hnsd-config.json, tests/docker/compose.hnsd.yml, and tests/acceptance/docker-hnsd-integration.sh add an opt-in hnsd topology separate from the deterministic fixture stack.
Live hnsd execution was not attempted because the Docker daemon is unavailable in this environment; the new script defaults to config/render validation unless ANYNS_RUN_DOCKER_HNSD_INTEGRATION=1 is set.
```

Git note:

```text
git add internal/plugins/hns/dns_backend.go internal/plugins/hns/plugin_test.go tests/acceptance/docker-hnsd-integration.sh tests/docker/anyns-hnsd-config.json tests/docker/compose.hnsd.yml BACKEND_STORAGE_AND_DOCKER_TEST_PLAN.md IMPLEMENTATION_STATUS.md GIT_PROGRESS.md && git commit -m "test: add hnsd docker integration topology"   FAIL; Git could not create .git/index.lock because the repository metadata is read-only. Latest committed hash remains 5abec9e.
```
