# anyNS 项目状态与计划偏差

日期：2026-06-11

本文件以最早的 [项目需求书](docs/00-项目需求书.md) 和
[开发路线与验收](docs/06-开发路线与验收.md) 为基线，记录服务器清理、
测试环境建设和 GitHub 交付后的实际状态。百分比是工程验收覆盖度估算，
不是工期完成率。

## 本次任务

- [x] 删除服务器上失效的 anyNS timer/service，并清除对应失败状态。
- [x] 清理历史 Codex 日志、锁/PID、Go/Python/pip 缓存、Docker 历史构建缓存和无用对象。
- [x] 服务器根分区占用从约 38 GiB 降至 33 GiB，可用空间从约 49 GiB 增至 54 GiB。
- [x] 确认服务器 Docker 29.1.3、Docker Compose 2.40.3 可用。
- [x] 确认 GitHub 连接器账号为 `wjcwqc`，对 `illegal-coder/anyNS` 有 admin/push 权限。
- [x] 确认本机和服务器没有可用的 GitHub SSH 私钥；交付改用已授权的 GitHub 连接器。
- [x] 将项目交付目标设为 `https://github.com/illegal-coder/anyNS`。
- [x] 将当前工程目标调整为可重复的即时 Docker 构建测试环境和测试用例。

## 当前测试目标

- [x] 每次测试只拉取外部基础镜像，本地 anyNS、证书生成器、DNS 工具和 Recursor 扩展镜像使用 `--pull --no-cache` 即时构建。
- [x] BIND 使用 9.20.23 Stable，PowerDNS Authoritative 使用 5.0.5，PowerDNS Recursor 使用 5.4.2。
- [x] 覆盖明文 DNS UDP/TCP 请求。
- [x] 覆盖证书校验的 DoT 和 DoH 请求。
- [x] 覆盖错误 TLS 主机名拒绝，避免把“加密但未认证”误认为安全 DNS。
- [x] 覆盖 ICANN 公网递归姿态、无路由 NXDOMAIN 和审计记录。
- [x] 覆盖 PowerDNS Authoritative 权威区。
- [x] 覆盖 `WALLET/TYPE262`、`HTTPS/SVCB`、DS、CAA、TXT 等现代记录。
- [x] 覆盖 HNS、Namecoin、ENS、Stacks BNS、Unstoppable、PNS-Polkadot、PulseChain PNS、SPACE ID、Solana SNS、TON DNS、Tezos Domains、Aptos Names、SuiNS、Freename、RIF/RNS、FIO、OpenAlias、ADA Handle、d.id/.bit，共 19 个插件的确定性后端契约。
- [x] 覆盖同后缀精确路由优先级，例如 d.id/.bit 与 Namecoin `.bit`。
- [x] 覆盖 denylist、sinkhole、DNS rebinding、异常/放大 RR、速率限制、高熵隧道行为和蜜罐转发。
- [x] 覆盖 DNSLog 查询、精确/模糊域名过滤、时间窗、排序、游标分页、聚合和指标。
- [x] 覆盖管理 API Bearer 权限、策略重载、缓存统计/清理和密钥元数据脱敏。
- [x] 覆盖蜜罐 503 失败、失败队列和监控指标。

## 2026-06-11 验收结果

- [x] `go test -buildvcs=false ./...`
- [x] `go vet ./...`
- [x] `bash tests/acceptance/check-local.sh`
- [x] `bash tests/acceptance/docker-hnsd-integration.sh` 的 compose/config 验证。
- [x] 从空容器栈执行 `bash tests/acceptance/docker-dns-integration.sh`，全部通过。
- [x] 完整 Docker 测试结束后没有运行中的容器。
- [x] Linux shell 语法检查通过。

## 最早路线完成度

- [x] **P0 基础环境，约 90%**：PowerDNS Recursor/Authoritative、插件运行时、管理 API、DNSLog、本机脚本、Compose、缓存、ICANN 姿态和现代 RR 已完成。尚缺真实正向/失效 DNSSEC 链的自动验收。
- [x] **P1 单一插件，约 85%**：HNS 主链路、NXDOMAIN、缓存、审计、失败边界和 fixture 测试已完成。live hnsd P2P/SPV 运行仍是 opt-in，未纳入确定性门禁。
- [x] **P2 插件并联，约 80%**：19 个插件、统一路由、优先级、缓存隔离和确定性 API/RPC 契约已测试。真实公网链节点/API 的凭据、配额、故障和数据一致性尚未验收。
- [x] **P3 安全防护，约 80%**：主要检测、拦截、DNSLog、蜜罐失败队列和指标已完成。NXDOMAIN flood/随机子域的持续流量阈值、CoreDNS profile 联调和压力测试仍待补充。
- [x] **P4 文档交付，约 75%**：需求、架构、插件、接口、安全、部署和验收文档已存在。生产密钥管理、真实外部后端运维、容量基线、升级/回滚演练记录仍待补充。
- [ ] **总体生产验收约 82%**：确定性开发/测试环境已可用，但不能把 fixture 全通过等同于真实链后端和生产流量验收完成。

## 相对最早计划的偏差

- [x] **开发顺序没有反转**：基础解析、HNS、插件并联、安全功能仍按 P0 -> P3 的依赖关系实现。
- [x] **测试门禁被前移并扩大**：本次优先完成即时构建、加密/明文 DNS、现代 RR、19 插件和安全链路的统一 Docker 验收。这是对原计划的增强，不是范围删除。
- [x] **真实重型后端改为确定性 fixture 优先**：符合服务器存储预算和最早计划中的“轻量后端优先”原则，但 live HNS、Namecoin 和其他链 RPC 的生产验收因此后移。
- [x] **BIND 从普通转发器扩展为 DoT/DoH 测试端点**：新增临时 CA、SAN 证书、正确主机名通过和错误主机名拒绝用例。
- [x] **WALLET 从文本近似值改为合法 TYPE262 wire 记录**：测试同时验证 BIND 解码后的币种和地址字符串。
- [x] **PowerDNS 版本和配置格式升级**：Recursor 使用 5.4 YAML 配置，并在自建镜像中安装 Lua HTTP/JSON 依赖。
- [ ] **原计划的 PowerDNS Web/Admin 后续阶段尚未开始**：按照现有 gate，应先完成 live HNS 和生产后端验证。

## 后续待办

- [ ] 增加真实 DNSSEC 有效链、bogus 链和 AD flag 自动测试。
- [ ] 在受控时间窗运行 `ANYNS_RUN_DOCKER_HNSD_INTEGRATION=1`，记录 hnsd 同步和查询结果。
- [ ] 为选定的生产插件增加真实外部 RPC/API smoke test，凭据仅通过 secret 注入。
- [ ] 增加 NXDOMAIN flood、随机子域、并发、长稳和容量基线测试。
- [ ] 启动 CoreDNS 可选安全 profile，并完成 AdGuard/DoT/DoH 上游联调。
- [ ] 完成生产密钥轮换、备份恢复、升级和回滚演练。
- [ ] 在上述 gate 通过后评估 PowerDNS Web/API 管理界面。
