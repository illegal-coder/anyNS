# anyNS Backend Storage And Docker Test Plan

Generated: 2026-06-04T23:18:00+08:00

## Server Capacity Snapshot

- Root filesystem: 87G total, 38G used, 49G available.
- Project directory after log compression: about 67M.
- `codex-continuous.log`: about 55M and intentionally left uncompressed so automation can append.
- Docker and Docker Compose are installed.

Conclusion: the server has enough space for source, test images, and lightweight resolver containers. It should not run multiple heavyweight full-chain nodes locally unless a storage budget is assigned.

## Backend Selection Rules

- Prefer lightweight, open-source, DNS-native backends first.
- Prefer fixture/mock containers for CI-like strict tests.
- Prefer public API or JSON-RPC adapters for large chain systems where local nodes are too expensive.
- Keep PowerDNS as the primary runtime path; backend containers should feed anyNS runtime, not bypass it.
- Do not leak matched decentralized names into ICANN fallback on backend failure, NXDOMAIN, NODATA, block, or rate-limit decisions.

## Minimal Backend Candidates

| Plugin | Status | Minimal backend path | Storage posture | Priority |
| --- | --- | --- | --- | --- |
| HNS `.hns` / `.hsd` | Implemented | `hnsd` container, then HNS `dns://` backend | Lightweight SPV resolver; suitable for this server | P0 |
| Namecoin `.bit` | Implemented | `ncdns` + Electrum-NMC/Namecoin lookup client, or mocked Namecoin Core JSON-RPC first | Avoid full Namecoin Core until storage/runtime measured | P0 |
| ENS `.eth` | Implemented | External Ethereum JSON-RPC endpoint or local fake JSON-RPC test server; deterministic Docker fixture now covers the current adapter contract | Avoid local Ethereum node | P1 |
| Unstoppable | Implemented | Resolution Service API or fake HTTP fixture | No local chain node | P1 |
| Stacks BNS | Implemented | Hiro-compatible API or fake HTTP fixture | No local Stacks node | P1 |
| PNS-Polkadot | Implemented | PNS REST API or fake HTTP fixture | No local chain node | P1 |
| PulseChain PNS | Implemented | External PulseChain JSON-RPC or fake JSON-RPC fixture; deterministic Docker fixture now covers the current adapter contract | Avoid local EVM node | P1 |
| Solana SNS | Implemented | QuickNode/SNS JSON-RPC or fake JSON-RPC fixture | Avoid local Solana node | P2 |
| SPACE ID | Implemented | SPACE ID Web3 Name API or fake HTTP fixture | No local chain node | P2 |
| TON DNS | Implemented | TON Center v3 DNS API or fake HTTP fixture | No local TON node | P2 |
| Tezos Domains | Implemented | Tezos Domains GraphQL or fake GraphQL fixture; deterministic Docker fixture now covers the current adapter contract | No local Tezos node | P2 |
| Aptos Names | Implemented | Aptos Names REST API or fake HTTP fixture; deterministic Docker fixture now covers the current adapter contract | No local Aptos node | P2 |
| SuiNS | Implemented | Sui JSON-RPC endpoint or fake JSON-RPC fixture | Avoid local Sui node | P2 |
| Freename/FNS | Implemented | Freename Resolution API or fake HTTP fixture | No local chain node | P3 |
| RIF/RNS | Implemented | RSK JSON-RPC or fake JSON-RPC fixture | Avoid local RSK node | P3 |
| FIO Handle | Implemented | FIO Chain API or fake HTTP fixture | No local FIO node | P3 |
| OpenAlias | Implemented | HTTP TXT lookup adapter or fake DNS/TXT adapter | Lightweight fixture first | P3 |
| ADA Handle | Implemented | ADA Handle API or fake HTTP fixture | No local Cardano node | P3 |
| d.id/.bit | Runtime-json only | Generic runtime JSON adapter | Needs concrete backend decision | P3 |

## Docker Network Test Topology

Primary deterministic compose file: `tests/docker/compose.dns-integration.yml`

Separate live/minimal HNS compose file: `tests/docker/compose.hnsd.yml`

Containers:

- `anyns-plugin-runtime`: runtime API with fixture backend config.
- `anyns-admin-api`: management API, admin-to-runtime proxy enabled, with fixture-scoped Bearer auth required for management/control-plane reads.
- `anyns-log-forwarder`: DNSLog ingestion and honeypot forwarding service, using the same deterministic failing honeypot fixture for queue/metrics assertions and fixture-scoped Bearer auth for audit/honeypot status reads.
- `pdns-recursor`: primary DNS path, Lua hook points to runtime.
- `pdns-authoritative`: local authoritative test zones and modern RR examples.
- `bind-latest`: ISC BIND 9.20 current-stable Docker image, used as a separate DNS client/recursive test component.
- `hnsd` or `hnsd-fixture`: HNS lightweight resolver path for `dns://` backend testing.
- `backend-fixtures`: deterministic Python HTTP fixture server for current HNS runtime-json responses, including a private-address rebinding sample, fake Namecoin Core JSON-RPC `.bit` responses, ENS JSON-RPC `.eth` responses, PulseChain PNS JSON-RPC `.pls` responses, Stacks/Hiro BNS API-style `.btc` zonefile responses, Unstoppable Domains Resolution API-style `.crypto` responses, PNS-Polkadot REST API-style `.dot` responses, SPACE ID Web3 Name API-style `.bnb` responses, TON Center v3 DNS API-style `.ton` responses, Tezos Domains GraphQL `.tez` responses, Aptos Names REST `.apt` responses, and a failing honeypot endpoint. It can be extended for more Wave 2/3 adapters.
- `dns-tools`: `dig`, `drill`, `kdig`, and curl-based smoke tests.

Minimum DNS assertions:

- `dig @pdns-recursor example.hns A` returns routed HNS answer.
- `dig @pdns-recursor missing.hns A` returns routed NXDOMAIN and does not fall through to ICANN.
- `dig @pdns-recursor example.bit A` returns the deterministic Namecoin JSON-RPC fixture answer.
- Runtime HTTP resolution for `www.example.bit A` returns the fixture subdomain answer from Namecoin `map`.
- `dig @pdns-recursor alice.eth TXT` and runtime HTTP `alice.eth WALLET` return deterministic ENS JSON-RPC fixture records through the `ens-json-rpc` adapter contract.
- `dig @pdns-recursor alice.btc TXT` and runtime HTTP `alice.btc WALLET` return deterministic Stacks BNS fixture records through the `stacks-bns-api` adapter contract.
- `dig @pdns-recursor alice.crypto TXT` and runtime HTTP `alice.crypto WALLET` return deterministic Unstoppable fixture records through the `unstoppable-resolution-api` adapter contract.
- `dig @pdns-recursor alice.dot TXT` and runtime HTTP `alice.dot WALLET` return deterministic PNS-Polkadot fixture records through the `pns-polkadot-api` adapter contract.
- `dig @pdns-recursor alice.pls TXT` and runtime HTTP `alice.pls WALLET` return deterministic PulseChain PNS JSON-RPC fixture records through the `pulsechain-pns-json-rpc` adapter contract.
- `dig @pdns-recursor alice.bnb TYPE262` confirms routed PowerDNS posture for the SPACE ID fixture while runtime HTTP `alice.bnb WALLET` returns deterministic `space-id-api` wallet records.
- `dig @pdns-recursor alice.ton TXT` and runtime HTTP `alice.ton WALLET` return deterministic TON DNS fixture records through the `toncenter-v3-dns` adapter contract.
- `dig @pdns-recursor alice.tez TXT` and runtime HTTP `alice.tez WALLET` return deterministic Tezos Domains fixture records through the `tezos-domains-api` GraphQL adapter contract.
- `dig @pdns-recursor alice.apt TYPE262` confirms routed PowerDNS posture for the Aptos Names fixture while runtime HTTP `alice.apt WALLET` returns deterministic `aptos-names-api` wallet records.
- `dig @pdns-recursor wallet.hns TYPE262` or runtime HTTP equivalent returns WALLET/TYPE262-compatible data.
- `dig @bind-latest example.hns A` forwards through the configured path and receives the same answer.
- ICANN domain such as `example.com` still resolves through normal recursive behavior when no anyNS route matches.
- Security denylist returns blocked `SERVFAIL`.
- Security sinkhole returns configured sinkhole `A` / `AAAA`.
- Reflection-amplification-prone `ANY` / `DNSKEY` queries return the runtime rate-limit `ResolveResult` contract and write a security audit event.
- DNSLog records include source plugin, rcode, risk/action, client view, tenant, and matched rule.
- Admin, runtime, and log-forwarder audit event reads honor inclusive RFC3339 `since` / `until` windows for known fixture events.
- Runtime and log-forwarder audit summaries aggregate retained events by plugin, RCODE, action, and top qname after fixture traffic is generated.
- Honeypot failed queue receives forwarded high-risk events when the fixture endpoint fails.
- Log-forwarder accepts `POST /api/v1/dns-events`, exposes filtered audit events, and reports DNSLog/honeypot metrics after forwarding to the failing fixture endpoint.
- Management endpoints reject unauthenticated admin/runtime/log-forwarder audit/control reads, accept integration-only scoped Bearer tokens without exposing token material in management key metadata, require a separate policy-writer token for admin/runtime policy reload, and require a separate cache operator token for proxied cache stats/flush.

HNS live/minimal backend assertions:

- `tests/docker/anyns-hnsd-config.json` points the HNS plugin at `dns://hnsd:53` without changing the deterministic fixture config.
- `tests/docker/compose.hnsd.yml` runs `anyns-plugin-runtime`, PowerDNS Recursor, BIND 9.20, `dns-tools`, and a lightweight `hnsd` image on an isolated Docker network.
- `tests/acceptance/docker-hnsd-integration.sh` validates compose rendering and anyNS config by default. Live hnsd execution is opt-in with `ANYNS_RUN_DOCKER_HNSD_INTEGRATION=1` because P2P/SPV bootstrap timing is slower and less deterministic than the fixture stack.
- The HNS `dns://` backend strips the anyNS routing suffix `.hns` / `.hsd` before sending the DNS wire query to hnsd-style alternate-root resolvers, then restores returned RR owner names to the original routed qname for the runtime/PowerDNS contract.

## Immediate Implementation Tasks

1. Done: add `tests/docker/compose.dns-integration.yml` with isolated Docker network and no host port conflicts by default.
2. Done: add `tests/docker/bind/named.conf` using the official ISC BIND 9.20 image as a test resolver/client.
3. Done: add `tests/docker/fixtures/` for no-secret fake HNS runtime-json and Namecoin JSON-RPC backend responses.
4. Done: add `tests/docker/anyns-config.json` as a dedicated Docker integration config so fixture routes do not alter the broad sample config.
5. Partially done: add `tests/acceptance/docker-dns-integration.sh` that:
   - checks Docker availability,
   - starts the compose stack,
   - runs DNS assertions from `dns-tools`,
   - collects logs on failure,
   - skips cleanly if Docker networking is unavailable.
   - Current scripted assertions cover HNS success, strict HNS `NXDOMAIN`, PowerDNS-routed Namecoin `.bit`, runtime-routed Namecoin subdomain data, PowerDNS/runtime-routed ENS `.eth` fixture records, PowerDNS/runtime-routed Stacks BNS `.btc` fixture records, PowerDNS/runtime-routed Unstoppable `.crypto` fixture records, PowerDNS/runtime-routed PNS-Polkadot `.dot` fixture records, PowerDNS/runtime-routed PulseChain PNS `.pls` fixture records, PowerDNS-routed/runtimed SPACE ID `.bnb` fixture records, PowerDNS/runtime-routed TON DNS `.ton` fixture records, PowerDNS/runtime-routed Tezos Domains `.tez` fixture records, PowerDNS/runtime-routed Aptos Names `.apt` fixture records, HNS `WALLET` and `TYPE262`, BIND-forwarded HNS, ICANN pass-through posture, authenticated admin-to-runtime proxy visibility, authenticated proxied admin plugin listing, redacted management-key metadata, admin/runtime policy reload authz plus management audit visibility, proxied admin cache stats/flush authz plus management audit visibility, admin/runtime/log-forwarder audit time-window filtering, admin/runtime/log-forwarder audit-summary aggregates, runtime security denylist/sinkhole/rebinding/reflection-rate-limit policy behavior, authenticated Namecoin/ENS/Stacks/Unstoppable/PNS-Polkadot/PulseChain PNS/SPACE ID/TON DNS/Tezos Domains/Aptos Names audit reads, runtime honeypot failed-queue metrics, and log-forwarder DNSLog ingestion/authenticated audit/authenticated honeypot-status/metrics/failed-queue behavior through the deterministic failing honeypot fixture.
6. Done: add HNS `hnsd` topology separately from deterministic fixture tests, because live P2P/SPV behavior can be slower and less deterministic. Runtime execution remains opt-in through `ANYNS_RUN_DOCKER_HNSD_INTEGRATION=1`.
7. Continue Namecoin path in two phases:
   - done: deterministic Namecoin JSON-RPC fixture for current adapter,
   - optional `ncdns`/Electrum-NMC or Namecoin Core integration after storage and setup cost is measured.

## PowerDNS Web/Admin Plan Gate

PowerDNS web frontend/admin work should be added after:

- Docker DNS integration test is passing or has a documented environment SKIP.
- HNS live/minimal backend path has been tested.
- Namecoin `.bit` has a deterministic fixture and a documented live backend path.
- Security, DNSLog, honeypot, management auth, policy reload, and metrics are tested in the Docker network path.

Planned scope when the gate is reached:

- Decide whether to enable PowerDNS built-in webserver/API in compose.
- Add admin API documentation for PowerDNS-facing controls.
- Add UI/API plan for zones, route/plugin status, audit summaries, and safe cache operations.
- Keep anyNS runtime as the source of truth for decentralized plugin routing, not the PowerDNS web UI.

## References

- ISC BIND 9 page: https://www.isc.org/bind/
- ISC official BIND Docker image: https://hub.docker.com/r/internetsystemsconsortium/bind9
- Handshake `hnsd`: https://github.com/handshake-org/hnsd
- Handshake `hsd`: https://github.com/handshake-org/hsd
- Namecoin `ncdns`: https://www.namecoin.org/docs/ncdns/
- Namecoin project repositories: https://github.com/namecoin
