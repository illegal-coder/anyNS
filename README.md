# anyNS

[![CI](https://github.com/illegal-coder/anyNS/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/illegal-coder/anyNS/actions/workflows/ci.yml)
[![Progress](https://img.shields.io/badge/production%20acceptance-88%25-yellow)](#功能与验收状态)
[![Go](https://img.shields.io/badge/Go-1.18%2B-00ADD8?logo=go)](go.mod)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Last commit](https://img.shields.io/github/last-commit/illegal-coder/anyNS)](https://github.com/illegal-coder/anyNS/commits/main)
[![Visitors](https://visitor-badge.laobi.icu/badge?page_id=illegal-coder.anyNS)](https://github.com/illegal-coder/anyNS)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/illegal-coder/anyNS)

anyNS 是基于 PowerDNS 的去中心化名称解析、DNS 安全与统一管理平台。项目由 PowerDNS Authoritative、PowerDNS Recursor、插件运行时、管理 API、React 管理界面和 DNSLog/蜜罐转发服务组成，覆盖传统 DNS、HNS、19 类去中心化名称插件、DNSSEC/DANE、EIP-3668 CCIP-Read、ACME DNS-01 和私有根 CA。

> 当前状态：确定性开发与隔离测试环境已经成熟，总体生产验收约 **88%**。`[x]` 表示功能已有实现，并有单元测试、集成测试、浏览器测试或可重复验收脚本作为证据；`[ ]` 表示尚未完成生产级或真实外部环境验收。

## 功能与验收状态

### DNS 核心与 PowerDNS

- [x] PowerDNS Authoritative 与 PowerDNS Recursor 一体化部署。
- [x] 默认 gsqlite3 可写权威后端，支持 Zone 创建、删除和记录管理。
- [x] PostgreSQL 17 / PowerDNS gpgsql 持久化部署模式。
- [x] Authoritative/Recursor 状态代理、Zone API、RRset API 和 Recursor 缓存清理。
- [x] 结构化 SOA 编辑，支持字段校验、serial 自动递增和 serial 回退拒绝。
- [x] 单标签 TLD、HNS Zone、Unicode/IDNA、apex NS、A/AAAA glue 全链路验收。
- [x] 明文 DNS UDP/TCP、DoT、DoH 和错误 TLS 主机名拒绝验收。
- [x] A、AAAA、NS、MX、SRV、SOA、CAA、DS、DNSKEY、TLSA、SVCB、HTTPS、TXT、URI 和 `WALLET/TYPE262` 等记录。
- [x] DNSSEC 密钥管理、DS 派生、DNSKEY/RRSIG、secure 链 `AD` 和 bogus 链 `SERVFAIL` 验收。
- [ ] 生产父区 DS 发布、真实替代根 trust anchor 分发和跨环境 DNSSEC 降级验收。

### 去中心化名称解析与路由

- [x] HNS DNS wire/backend、NXDOMAIN、缓存、审计和失败边界。
- [x] opt-in live hnsd P2P/SPV 链路：hnsd → anyNS Runtime → PowerDNS Recursor → BIND DNS/DoT/DoH。
- [x] 19 个插件的确定性适配器契约、统一路由、优先级、fallback 和缓存隔离。
- [x] 已覆盖插件：HNS、ENS、Namecoin `.bit`、Stacks BNS、Polkadot/PulseChain PNS、Unstoppable Domains、Solana SNS、SPACE ID、TON DNS、Tezos Domains、Aptos Names、SuiNS、Freename FNS、RIF RNS、FIO Handle、OpenAlias、ADA Handle 和 DID.bit。
- [x] EIP-3668 CCIP-Read、REST、JSON-RPC、GraphQL、DNS wire 和静态 fixture 类型后端。
- [ ] 为选定插件建立带 secret 注入的真实公网 RPC/API smoke gate。
- [ ] 使用已同步 hnsd 或可控 live 名称补充稳定的正向 `NOERROR` 链上解析证据。
- [ ] 将更多真实去中心化组件纳入可选 Compose profile 和最低生产模式门禁。

### 管理 API 与 Web 控制台

- [x] React/Vite 管理界面已嵌入 `anyns-admin-api`，支持 SPA fallback。
- [x] Dashboard、PowerDNS、Zone、DNS 记录、SOA、插件、安全、审计、配置和证书页面。
- [x] `/api/v1/capabilities` 按 scope、后端可用性和配置可写性返回 hidden/readonly/readwrite 状态。
- [x] 基于角色、细粒度 scope、API Key 生命周期和客户端 CIDR 的管理鉴权模型。
- [x] 配置写入时保留服务端密钥，并触发 Runtime reload。
- [x] 插件启用、停用、策略重载、缓存清理和审计查询。
- [x] 桌面端和移动端 Selenium/Chromium 验收，覆盖 Unicode HNS Zone、SOA、插件、只读配置和证书摘要。
- [ ] 完成 Cloudflare 风格 DNS/SSL 控制面组件拆分和完整浏览器工作流验收。
- [ ] 完成生产 TLS 入口、统一身份接入和密钥轮换演练。

### DNS 安全、审计与蜜罐

- [x] denylist、allowlist、sinkhole 和 DNS rebinding 阻断。
- [x] DNS 隧道、DGA、高熵/超长标签、随机子域、NXDOMAIN 异常检测。
- [x] 查询速率限制、异常 RR 和反射放大策略。
- [x] allow、log-only、block、sinkhole、rate-limit、honeypot-forward 和 tag-and-continue 动作。
- [x] DNSLog 持久化、过滤、排序、游标分页、聚合、延迟统计和指标。
- [x] 蜜罐 API Key/HMAC 对接、重试、最大尝试次数和失败队列。
- [x] 管理 API scope 越权回归测试、私钥/PEM/路径非披露测试。
- [x] CI 源码策略扫描：固定 Action SHA、workflow 权限、私钥 PEM、pipe-to-shell、privileged/host runtime、弱 hash、`InsecureSkipVerify` 和 shell command construction。
- [ ] 完成长稳、压力、容量、NXDOMAIN flood 和大规模随机子域基线。
- [ ] 完成生产日志归档、告警、蜜罐容量和失败队列清理策略。

### 证书、DNSSEC 与私有信任

- [x] ACME DNS-01 作业状态机、幂等、有限重试、续期、吊销和持久化。
- [x] PowerDNS DNS-01 TXT 写入、传播检查、清理和无权威区失败路径。
- [x] TLSA 生成/发布和 DNSSEC/DANE 联动。
- [x] 独立 `private-ca` issuer，使用 Go `crypto/x509` clean-room 实现。
- [x] 私有根创建、加载、导入、轮换、禁用/启用、指纹和备份状态。
- [x] 私有根公开证书下载、信任交接和 trust-store 操作员交接。
- [x] 叶证书签发、清单、强制续期、吊销、CRL Distribution Point、公开 CRL 和作业级 OCSP。
- [x] 根/叶私钥 `0600`、证书下载不含私钥、重启和 Docker-volume 恢复验收。
- [x] HNS 单标签 TLD + DNSSEC + private CA + HTTPS + TLSA + OCSP + CRL 一体化演示门禁。
- [ ] 自动续期 scheduler、证书部署 hook 和 OCSP stapling。
- [ ] 跨主机私有 CA 灾备、真实 trust store 恢复和根轮换分发演练。
- [ ] 公开 WebPKI 与生产父区 DNSSEC 的真实环境联合验收。

### CI、交付与运维

- [x] GitHub Actions 并行执行 Go test/vet/build、前端 unit/ESLint/build、源码策略、shell 和 Compose model 门禁。
- [x] CI 第三方 Action 固定到不可变 SHA，构建产物保留 7 天。
- [x] gpgsql 空库初始化、逻辑备份和恢复验收。
- [x] 固定镜像摘要、预升级备份、失败升级和 SQL 回滚验收。
- [x] Docker 内 source/target 灾备：gpgsql 数据与 private-ca 证书卷恢复。
- [x] 短程 DNS/API 循环、private-ca 批量签发和资源快照 load/soak 门禁。
- [ ] 使用标准 gc Go 工具链补跑 `go test -race` 门禁；服务器现有 gccgo 1.18 无法完成该 gate。
- [ ] 完成生产全栈升级、跨主机灾备和恢复时间/恢复点目标演练。
- [ ] 完成 GitHub Support 旧 SHA 缓存对象清除与复核。

## 系统组成

| 组件 | 用途 | 默认宿主机端口 |
| --- | --- | --- |
| `pdns-recursor` | 递归解析、缓存、DNSSEC 验证和 Lua 路由 | `127.0.0.1:53/udp,tcp`，API `8084` |
| `pdns-authoritative` | 权威 Zone、RRset、DNSSEC 和 DNS-01 | DNS `127.0.0.1:5300`，API `8083` |
| `anyns-plugin-runtime` | 去中心化插件路由、安全分析和解析 API | `127.0.0.1:8081` |
| `anyns-admin-api` | 管理 API、权限控制和内嵌 Web 控制台 | `127.0.0.1:8080` |
| `anyns-log-forwarder` | DNSLog、蜜罐转发、重试和失败队列 | `127.0.0.1:8082` |
| `pdns-postgres` | 可选 gpgsql 持久化后端 | 仅 Compose 内部网络 |
| `coredns-security` | 可选 CoreDNS 安全 profile | `127.0.0.1:5353` |

所有管理和测试端口默认只绑定回环地址。远程访问应使用 TLS 反向代理、VPN 或 SSH tunnel，不应直接把管理 API 暴露到公网。

## 快速部署

### 前置条件

- Linux 服务器或支持 Linux 容器的 Docker 环境。
- Docker Engine 与 Docker Compose v2。
- Git。
- 源码构建/验证需要 Go 1.18+；前端开发构建使用 Node.js 22。

### 1. 获取代码并准备配置

```bash
git clone https://github.com/illegal-coder/anyNS.git
cd anyNS
cp .env.example .env
```

编辑 `.env`，至少替换所有 `change-me`：

```dotenv
ANYNS_BIND_ADDRESS=127.0.0.1
PDNS_RECURSOR_API_KEY=<openssl rand -hex 32>
PDNS_AUTH_API_KEY=<openssl rand -hex 32>
PDNS_AUTH_WEBSERVER_PASSWORD=<openssl rand -hex 32>
ANYNS_HONEYPOT_API_KEY=<openssl rand -hex 32>
ANYNS_HONEYPOT_HMAC_SECRET=<openssl rand -hex 32>
ANYNS_MANAGEMENT_AUTH_REQUIRED=true
ANYNS_MANAGEMENT_API_KEY=<openssl rand -hex 32>
```

不要把 `.env`、API Key、私有根、账户密钥、叶证书私钥或数据库备份提交到 Git。

### 2. 启动默认完整栈（gsqlite3）

```bash
docker compose --env-file .env config --quiet
docker compose --env-file .env up -d --build --wait
docker compose --env-file .env ps
```

默认 Compose 会初始化配置卷、PowerDNS gsqlite3 数据库和 `anyns.test.` 测试区，然后启动 Recursor、Authoritative、Runtime、Admin 和 Log Forwarder。

### 3. 健康检查与解析验证

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8081/healthz
curl -fsS http://127.0.0.1:8082/healthz

dig @127.0.0.1 anyns.test SOA
dig @127.0.0.1 www.anyns.test A
```

管理界面：

```text
http://127.0.0.1:8080/
```

服务器只绑定回环地址时，可建立 SSH tunnel：

```bash
ssh -L 8080:127.0.0.1:8080 user@server
```

然后在本机访问 `http://127.0.0.1:8080/`。启用管理鉴权后，API 使用：

```http
Authorization: Bearer <management-api-key>
```

### 4. PostgreSQL/gpgsql 完整栈

先在 `.env` 中设置强随机数据库密码和 PowerDNS 密钥：

```dotenv
PDNS_POSTGRES_DB=pdns
PDNS_POSTGRES_USER=pdns
PDNS_POSTGRES_PASSWORD=<strong-random-secret>
PDNS_GPGSQL_DNS_PORT=5301
PDNS_GPGSQL_API_PORT=8085
```

使用 Compose 叠加文件启动完整栈：

```bash
docker compose --env-file .env \
  -f docker-compose.yml \
  -f docker-compose.gpgsql.yml \
  config --quiet

docker compose --env-file .env \
  -f docker-compose.yml \
  -f docker-compose.gpgsql.yml \
  up -d --build --wait
```

仅部署 PostgreSQL + PowerDNS Authoritative：

```bash
docker compose --env-file .env \
  -f docker-compose.gpgsql.yml \
  up -d --wait
```

数据默认保存在 `anyns-pgsql-data` volume。生产环境应把 `PDNS_POSTGRES_DATA` 指向受控的命名卷或宿主机存储策略，并配置独立备份。

### 5. 可选 CoreDNS 安全 profile

```bash
docker compose --env-file .env \
  --profile coredns-security \
  up -d --build --wait
```

### 6. 停止与清理

```bash
docker compose --env-file .env down
```

不要在生产环境随意使用 `down -v`；该参数会删除配置、PowerDNS、证书、缓存和日志队列等持久化卷。

## 关键配置

### 环境变量

| 配置 | 说明 |
| --- | --- |
| `ANYNS_BIND_ADDRESS` | 宿主机监听地址，默认 `127.0.0.1` |
| `ANYNS_CONFIG_FILE` | anyNS JSON 配置文件路径 |
| `ANYNS_MANAGEMENT_AUTH_REQUIRED` | 是否强制管理 API 鉴权；生产必须为 `true` |
| `ANYNS_MANAGEMENT_API_KEY` | 单 Key 快速部署；多角色/多 Key 使用 JSON 配置 |
| `PDNS_AUTH_API_KEY` | PowerDNS Authoritative API Key |
| `PDNS_RECURSOR_API_KEY` | PowerDNS Recursor API Key |
| `ANYNS_HONEYPOT_URL` | 蜜罐事件接收地址；留空表示不转发 |
| `ANYNS_HONEYPOT_API_KEY` | 蜜罐 API Key |
| `ANYNS_HONEYPOT_HMAC_SECRET` | 蜜罐事件 HMAC 密钥 |
| `ANYNS_DNSLOG_PATH` | DNSLog JSONL 持久化路径 |
| `ANYNS_HONEYPOT_FAILED_QUEUE_PATH` | 蜜罐失败队列路径 |
| `ICANN_FORWARDERS` | ICANN 域名上游，使用分号分隔 |

主配置模板位于 [`configs/anyns/config.example.json`](configs/anyns/config.example.json)，包括插件、路由、安全策略、PowerDNS、管理角色/API Key、DNSLog、蜜罐和证书配置。首次启动时，`anyns-config-init` 会把模板复制到 `anyns-config` volume。

### 管理权限

管理 API 支持以下 scope：

- `management:read`
- `powerdns:read` / `powerdns:write`
- `plugins:read` / `plugins:write`
- `cache:read` / `cache:write`
- `audit:read`
- `config:read` / `config:write`
- `policy:write`
- `honeypot:read` / `honeypot:write`
- `certificates:read` / `certificates:write`

多角色、多 Key、有效期、吊销、轮换和客户端 CIDR 限制由 `management.roles`、`management.keys` 及 `anyns-management-key` 工具管理。详细模型见 [`docs/03-接口与数据模型.md`](docs/03-接口与数据模型.md)。

### 证书模式

证书功能默认关闭。启用前必须明确选择：

- `issuer_mode: "acme"`：公开 WebPKI DNS-01。先使用 staging CA，配置账户邮箱并显式接受 TOS。
- `issuer_mode: "private-ca"`：HNS、内网或受控客户端的私有信任，不会获得公开浏览器信任。

证书和私钥保存在 `/var/lib/anyns/certificates` 对应的持久化数据卷中。私有根模式必须备份整个目录、核对根指纹并由操作员显式分发 trust store；根轮换不会自动更新客户端信任。

完整配置、API、CRL、OCSP、TLSA 和信任边界见 [`docs/09-去中心化验证与证书运维.md`](docs/09-去中心化验证与证书运维.md)。

## 数据持久化与备份

| Volume | 内容 |
| --- | --- |
| `anyns-config` | 运行配置 |
| `anyns-auth-data` | 默认 gsqlite3 PowerDNS 数据 |
| `anyns-pgsql-data` | 可选 PostgreSQL/gpgsql 数据 |
| `anyns-recursor-cache` | Recursor 缓存 |
| `anyns-runtime-data` | Runtime 状态 |
| `anyns-admin-data` | 管理状态和证书存储 |
| `anyns-log-queue` | DNSLog/蜜罐失败队列 |

gpgsql 逻辑备份示例：

```bash
set -a
. ./.env
set +a

BACKUP_FILE="/path/to/protected-backups/pdns-$(date -u +%Y%m%dT%H%M%SZ).sql"
docker compose --env-file .env -f docker-compose.gpgsql.yml \
  exec -T pdns-postgres \
  pg_dump --clean --if-exists \
  --username="$PDNS_POSTGRES_USER" \
  --dbname="$PDNS_POSTGRES_DB" >"$BACKUP_FILE"
test -s "$BACKUP_FILE"
```

备份必须写入受控目录并执行恢复验证。private-ca 部署还必须独立备份证书 volume；不能只备份数据库。完整恢复、升级和回滚步骤见 [`docs/05-部署与对接流程.md`](docs/05-部署与对接流程.md)。

## 构建与验证

### 本地快速门禁

```bash
GOTOOLCHAIN=local GOMAXPROCS=1 go test -buildvcs=false -p=1 ./...
GOTOOLCHAIN=local GOMAXPROCS=1 go vet -buildvcs=false -p=1 ./...
bash tests/acceptance/check-local.sh

cd web/admin
npm ci
npm test
npm run check
npm run build
```

也可以运行：

```bash
bash scripts/bootstrap-local.sh
```

### Docker 验收

```bash
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/docker-dns-integration.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/docker-soa-tld.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/docker-dnssec-validation.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/docker-gpgsql-backup-restore.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/docker-gpgsql-upgrade-rollback.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/docker-disaster-recovery.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/docker-load-soak.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/selenium-admin.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/decentralized-certificates.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/private-ca-certificates.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/hns-private-ca-demo.sh
```

live hnsd 验收需要显式 opt-in：

```bash
ANYNS_RUN_DOCKER_HNSD_INTEGRATION=1 \
  bash tests/acceptance/docker-hnsd-integration.sh
```

所有证书验收使用独立 Compose project、回环端口、测试区、Pebble 测试 CA 或一次性私有根 CA，不应接触生产配置和真实密钥。

## 生产部署检查表

- [ ] 所有 `change-me` 已替换，secret 未进入 Git、镜像层和日志。
- [ ] `ANYNS_MANAGEMENT_AUTH_REQUIRED=true`，角色、scope、Key 有效期和客户端 CIDR 已审核。
- [ ] 管理入口仅通过受控 TLS 反向代理、VPN 或 SSH tunnel 暴露。
- [ ] PowerDNS API 仅在内部网络可达，API Key 已独立设置。
- [ ] PostgreSQL、PowerDNS、配置、证书和失败队列已纳入备份。
- [ ] 已完成一次恢复演练，并记录 RPO/RTO、镜像摘要和 Compose 渲染结果。
- [ ] ACME 已先通过 staging；private-ca 已完成根指纹核对、备份和 trust store 交接。
- [ ] DNSSEC 父区 DS/trust anchor、DoT/DoH 证书和降级路径已在目标环境验证。
- [ ] 真实插件 RPC/API、超时、限流、凭据轮换和故障 fallback 已验证。
- [ ] 指标、日志保留、告警、容量和长稳测试已完成。

## 项目目录

```text
cmd/                    服务与运维命令
internal/               核心实现
web/admin/              React/Vite 管理界面
configs/                anyNS、PowerDNS 和 CoreDNS 配置
tests/acceptance/       可执行验收脚本
tests/docker/           隔离 Docker 测试拓扑
docs/                   需求、架构、接口、安全、部署和验收文档
docker-compose.yml      默认完整栈
docker-compose.gpgsql.yml
```

## 文档

- [项目需求书](docs/00-项目需求书.md)
- [总体架构需求](docs/01-总体架构需求.md)
- [去中心化插件需求](docs/02-去中心化插件需求.md)
- [接口与数据模型](docs/03-接口与数据模型.md)
- [DNS 安全与蜜罐联动](docs/04-DNS安全与蜜罐联动.md)
- [部署与对接流程](docs/05-部署与对接流程.md)
- [开发路线与验收](docs/06-开发路线与验收.md)
- [需求覆盖核对表](docs/07-需求覆盖核对表.md)
- [HNS 网页托管与 DNS 记录管理](docs/08-HNS网页托管与DNS记录管理.md)
- [去中心化验证与证书运维](docs/09-去中心化验证与证书运维.md)
- [当前高优先级路线](docs/10-当前高优先级路线.md)
- [项目状态](PROJECT_STATUS_2026-06-12.md)
- [变更记录](CHANGELOG.md)

仓库最低 Go 版本保持 `1.18`。依赖必须能由 Go 1.18/gccgo 解析和构建，不能通过本地升级工具链掩盖兼容问题。
