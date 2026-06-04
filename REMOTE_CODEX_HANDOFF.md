# anyNS 远端 Codex 交接说明

## 当前状态

当前项目已完成需求与分部文档编写，代码实现尚未开始。文档位于 `docs/`：

- `docs/00-项目需求书.md`
- `docs/01-总体架构需求.md`
- `docs/02-去中心化插件需求.md`
- `docs/03-接口与数据模型.md`
- `docs/04-DNS安全与蜜罐联动.md`
- `docs/05-部署与对接流程.md`
- `docs/06-开发路线与验收.md`
- `docs/07-需求覆盖核对表.md`
- `docs/99-参考资料.md`

## 远端开发目标

请基于需求文档继续实现 anyNS 的首版工程骨架，按以下优先级推进：

1. P0 基础环境：PowerDNS Recursor + Authoritative、插件运行时、管理 API、DNSLog 管线、Docker Compose、本机一键部署脚本。
2. P1 单一插件：实现 Handshake/HNS 样板插件和统一插件接口。
3. P2 插件并联：实现插件路由、优先级、同后缀冲突、缓存隔离和 RPC/API 故障隔离。
4. P3 安全防护：实现 DNS tunneling、DGA、高熵、NXDOMAIN flood、DNS rebinding、异常 RR 和反射放大拦截。
5. P4 文档交付：补齐实际部署命令、配置样例、验收测试和升级回滚。

## 架构约束

- PowerDNS 是主链路和去中心化插件承载层。
- CoreDNS 仅作为低优先级可选安全增强 profile。
- ICANN 公网递归解析必须默认可用。
- 所有插件必须统一输出 RRSet、RCODE、TTL、来源插件、安全标签和审计元数据。
- `WALLET` 是 IANA DNS RR type 262，不是 `.wallet` 后缀。
- AdGuard/审计 DNS 通过上游 DNS、DoH/DoT、Webhook、日志导出和策略 API 对接。
- 蜜罐 API 使用 `POST /api/v1/dns-events`，支持 API Key/HMAC、批量、重试、幂等和失败队列。

## 建议首批代码交付

- `docker-compose.yml`
- `.env.example`
- `configs/pdns-recursor/`
- `configs/pdns-authoritative/`
- `configs/coredns/`
- `cmd/anyns-admin-api/`
- `cmd/anyns-plugin-runtime/`
- `internal/plugins/`
- `internal/plugins/hns/`
- `internal/dnslog/`
- `internal/honeypot/`
- `internal/security/`
- `scripts/bootstrap-local.ps1`
- `scripts/bootstrap-local.sh`
- `tests/acceptance/`

## 远端 Codex 建议启动提示

```text
请读取当前目录 docs/ 下的 anyNS 需求文档和 REMOTE_CODEX_HANDOFF.md，继续实现首版代码工程。
优先完成 P0 基础环境和 P1 HNS 样板插件：
1. 选择适合 PowerDNS 插件运行时、管理 API 和 DNSLog 管线的项目结构。
2. 添加 Docker Compose、配置样例和本机一键部署脚本。
3. 实现统一插件接口和 HNS 插件骨架。
4. 实现 DNSLog 事件模型和蜜罐 API 客户端骨架。
5. 实现 DNS 安全规则接口和基础规则样例。
6. 添加验收测试或最小可运行检查。
完成后运行格式化、静态检查和可执行的基础测试。
```
