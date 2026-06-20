# anyNS 项目状态与计划偏差

日期：2026-06-12

## 2026-06-18 优先级调整

- [x] 将 SOA、单标签 HNS 顶级权威区、NS/glue 和 serial 正确性提升为 P0。
- [x] 将证书清单、ACME、私有根 CA 与叶证书签发提升为 P0，并明确公开信任与私有信任边界。
- [x] 采用 clean-room 方式重写 certy 类功能，不复制 `eskimo/certy` 源码或 PKI.js。
- [x] 将 Cloudflare 风格的 Zone/DNS/SOA/DNSSEC/SSL-TLS 工作流列为 P1。
- [x] 增加 GitHub Actions 快速门禁规划，覆盖 Go、前端、shell 与 Compose model。
- [x] GitHub Actions 快速门禁已在 `main` 连续通过，并固定第三方 Action SHA、显式缓存依赖和 7 天构建产物保留期。
- [ ] 完成 SOA/TLD 全链路测试矩阵。
- [ ] 完成 private-ca 根证书生命周期、叶证书签发和安全测试。
- [ ] 完成 DNS/SSL 控制面组件拆分和浏览器验收。

详细执行顺序见 `docs/10-当前高优先级路线.md`。

本文件以 `docs/00-项目需求书.md`、`docs/06-开发路线与验收.md` 为最早计划基线。百分比为工程验收覆盖度估算，不代表工期。

## 当前任务完成度

- [x] 后续代码以服务器 `/root/anyNS` 为唯一写入工作区。
- [x] 将前序本地改动同步到服务器并纳入安全重写后的 Git 历史。
- [x] 在服务器配置 Git 身份、GitHub CLI 凭据助手和仓库推送权限。
- [x] 使用 Gitleaks、TruffleHog 和自定义规则扫描当前工作区及完整历史。
- [x] 从 Git 历史移除服务器地址、运维路径、代理拓扑、Codex 运行脚本和状态文件。
- [x] 强制更新 GitHub `main` 到清理后的历史，并用全新 clone 复核泄露扫描为 0。
- [ ] GitHub 仍可能按旧 SHA 暂存不可达对象；已生成 support purge 请求，待 GitHub Support 清除缓存对象。
- [x] 清理失效 timer/service、历史构建缓存、日志和无用 Docker 对象。
- [x] 确认服务器 Docker、Compose、GitHub 账号及 `illegal-coder/anyNS` 管理权限。
- [x] 将当前工程目标调整为即时 Docker 构建测试环境与自动化测试用例。
- [x] 完善 PowerDNS Authoritative/Recursor 后端代理 API、状态、区域和缓存管理。
- [x] 增加可写配置 API，保存时保留服务端密钥并触发 Runtime 重载。
- [x] 开发 React/Vite 管理页面，覆盖总览、PowerDNS、插件、安全、审计和配置。
- [x] 将前端静态资源集成进 `anyns-admin-api`，提供 SPA fallback 和静态资源缓存策略。
- [x] 浏览器验证 Zone 创建/删除、配置保存/重载、服务状态和控制台错误。
- [x] 应用内浏览器验证 capability 菜单、PowerDNS 页面、无框架错误覆盖层及控制台 0 error/warn；截图接口超时，DOM/交互证据有效。
- [x] `bash tests/acceptance/selenium-admin.sh` 使用最新 Selenium Chromium 镜像完成隔离 Docker 联调。
- [x] 主环境使用 PowerDNS gsqlite3 backend，实现真实 Zone 创建和删除。
- [x] 增加独立 PostgreSQL 17.5/PowerDNS gpgsql 部署模式，默认端口仅绑定回环地址并使用持久化数据卷。
- [x] BIND 9.20 协议验收使用独立 bind backend 配置，避免与可写管理环境耦合。
- [x] Admin、Runtime、日志、PowerDNS API 和测试 DNS 端口默认仅绑定回环地址。
- [x] 在服务器私有目录部署每 5 小时一次的 Codex systemd 自动开发任务，包含互斥、单次时限和连续两次额度耗尽自动停用。
- [x] 新增 `/api/v1/capabilities`，按 scope、后端配置和配置文件可写性返回 hidden/unavailable/readonly/readwrite。
- [x] 网站菜单、页面入口和写按钮按后端 capability 自动隐藏或只读降级。
- [x] 修复 Admin 代理 Runtime 后 dashboard 仍显示进程本地插件状态的问题。
- [x] 增加前端能力映射单元测试和独立 Selenium/Chromium Docker 联调拓扑。
- [x] Selenium 覆盖桌面菜单、PowerDNS 页面、插件启停与恢复、只读配置和移动端导航。
- [x] 修复移动端 Toast 遮挡侧栏导航的问题。
- [x] 修复 Dashboard 仅校验 `management:read` 却返回越权 PowerDNS、插件、缓存、审计和配置数据的问题，按细粒度读取 scope 裁剪响应。
- [x] 修复 capability 响应额外要求 `management:read`、导致仅持有合法细粒度读取 scope 的用户无法使用对应管理页面的问题；增加 PowerDNS、插件、审计、配置和缓存读取权限矩阵回归测试。
- [x] 将 PowerDNS capability 拆分为 Authoritative 与 Recursor 后端状态；仅配置单一后端时，管理页面只启用对应的 Zone/记录管理或缓存清理操作。
- [x] 增加结构化 SOA 编辑 API 与管理页面，支持字段级校验、显式 serial 防回退、空 serial 自动递增、审计事件和桌面端 Selenium 回归覆盖。
- [x] 增加 `private-ca` 证书 issuer mode，与 ACME DNS-01 显式分离；本地私有根 CA 使用 Go `crypto/x509` clean-room 生成/加载并签发 serverAuth 叶证书链。
- [x] 增加 `GET /api/v1/certificates/private-ca/root` 元数据 API，仅返回私有根 CA subject、serial、有效期、SHA-256 指纹、SKI/AKI、KeyUsage 和根私钥权限状态，不返回 PEM 或私钥。
- [x] 增加 `PATCH /api/v1/certificates/private-ca/root` 生命周期控制，支持禁用/启用私有根 CA；禁用状态持久化并阻止新的 private-ca 叶证书签发。
- [x] 增加 `POST /api/v1/certificates/private-ca/root/backup-status`，用当前根 CA SHA-256 指纹记录操作员备份证据；根元数据返回 `missing`、`current` 或 `stale`，不返回备份路径、PEM 或私钥。

## 测试与验收

- [x] `npm run check`
- [x] `npm run build`
- [x] `npm test`（能力清单缺失、只读和隐藏菜单映射）
- [x] `go test -buildvcs=false ./...`
- [x] `go vet ./...`
- [x] `bash tests/acceptance/check-local.sh`
- [x] Dashboard scope 回归测试验证仅有 `management:read` 的凭据无法读取其他功能数据。
- [x] Capability scope 回归测试验证细粒度读取凭据只显示其可访问功能，并继续隐藏 overview 和无关功能。
- [x] PowerDNS capability 回归测试覆盖仅 Authoritative、仅 Recursor 和旧版聚合 capability 前端兼容。
- [x] PowerDNS SOA 回归测试覆盖 serial 自动递增、显式 serial 回退拒绝、字段边界校验和 Admin API 代理写入。
- [x] Private CA 回归测试覆盖根 CA BasicConstraints/KeyUsage/SKI-AKI、根私钥 `0600`、根加载复用、叶证书 SAN/serverAuth/非 CA 约束，以及 Admin API 证书下载不返回私钥。
- [x] Private CA root metadata 回归测试覆盖 package/API 两层输出，验证指纹、KeyUsage、根私钥权限状态，并断言不含 PEM 或 private key material。
- [x] Private CA root disable 回归测试覆盖禁用状态持久化、禁用后签发失败、重新启用后恢复签发，以及管理审计不包含 PEM 或私钥。
- [x] Private CA root backup-status 回归测试覆盖缺失、指纹不匹配拒绝、匹配后 `current`、旧标记 `stale`，以及管理审计不包含 PEM 或私钥。
- [x] Private CA 并发签发回归测试覆盖多个同时提交的签发任务全部进入 issued 清单、有效期窗口存在、公开清单不泄露 idempotency key，并验证底层 issuer 最大并发为 1。
- [x] `bash tests/acceptance/private-ca-certificates.sh` 使用隔离 Compose profile 验证 private CA Admin 镜像构建、叶证书签发、证书链校验、证书下载私钥非披露、根/叶私钥权限、重启持久化和容器内备份恢复。
- [x] `bash tests/acceptance/private-ca-certificates.sh` 现扩展验证 private CA 证书清单、有效期窗口、TLSA 生成不发布、强制续期与 `renewal_of`、原证书吊销、吊销后禁止续期、吊销证书下载私钥非披露，以及重启和备份恢复后的状态持久化。
- [x] `bash tests/acceptance/selenium-admin.sh` 验证 capability-aware 管理流程及 Unicode HNS Zone/记录增删交互。
- [x] `bash tests/acceptance/selenium-admin.sh` 现包含移动端 HNS 单标签 Zone 创建、SOA Refresh 修改、SOA 记录表刷新和测试 Zone 清理恢复。
- [x] `bash tests/acceptance/docker-soa-tld.sh` 使用一次性 gsqlite/Recursor 拓扑验证 2 个单标签 HNS Zone（ASCII/Unicode IDNA）、apex SOA/NS、A/AAAA glue、非法子 Zone 400、Authoritative AA、递归一致性和 serial 递增，并在结束后删除测试卷。
- [x] `bash tests/acceptance/docker-soa-tld.sh` 现扩展验证 `example.` 单标签 TLD 经 BIND 明文 DNS、DoT 和 DoH 的 SOA 响应，且错误 DoT 证书主机名会被拒绝。
- [x] `bash tests/acceptance/docker-hnsd-integration.sh` 默认 no-live 模式验证 hnsd/Recursor/BIND DoT/DoH profile model；live hnsd 运行仍需显式 `ANYNS_RUN_DOCKER_HNSD_INTEGRATION=1`。
- [x] `ANYNS_RUN_DOCKER_HNSD_INTEGRATION=1 bash tests/acceptance/docker-hnsd-integration.sh` 在服务器隔离 Docker 网络中验证 live hnsd -> anyNS Runtime `hns` 路由 -> PowerDNS Recursor -> BIND 明文 DNS/DoT/DoH 链路；新 hnsd 未同步时接受 `SERVFAIL`，并验证不使用 static HNS fixture。
- [x] GitHub Actions `CI` 验证 Go test/vet/build、前端 unit/ESLint/build、shell 语法及全部隔离 Compose model（含 SOA/TLD），并上传短期构建产物。
- [ ] 服务器当前仅提供 `go1.18 gccgo`；`go test -race -buildvcs=false ./internal/adminapi` 在生成 `testmain` 时失败为 `package testmain: cannot find package`，尚需使用标准 gc Go 工具链补跑 race gate。
- [x] `docker compose config --quiet`
- [x] `bash tests/acceptance/docker-gpgsql-backup-restore.sh` 验证 gpgsql 空库初始化、健康检查、DNS 查询、逻辑备份、数据变更和恢复。
- [x] `bash tests/acceptance/docker-gpgsql-upgrade-rollback.sh` 使用临时 PostgreSQL 数据目录验证固定镜像摘要、预升级备份、失败升级数据变更、SQL 回滚、权威 DNS 答案恢复和 PowerDNS API 健康恢复。
- [x] `bash tests/acceptance/docker-disaster-recovery.sh` 使用独立 source/target Compose projects 验证 gpgsql SQL 备份恢复和 private-ca 证书存储 Docker-volume 备份恢复，目标环境 DNS/API 和证书清单恢复，且证书下载仍不包含私钥。
- [x] `docker compose build --pull --no-cache`
- [x] 主 Compose 从空 PowerDNS 数据卷初始化并全部健康。
- [x] PowerDNS `anyns.test.` 区域校验 0 errors，Authoritative/Recursor 查询一致。
- [x] 管理 API Zone 创建返回 201、删除返回 204。
- [x] 配置 PUT 保存成功并返回 Runtime reload `loaded`。
- [x] Recursor 缓存清理 API 返回 200。
- [x] `bash tests/acceptance/docker-dns-integration.sh` 从无缓存即时构建并全部通过。
- [x] 覆盖明文 DNS UDP/TCP、DoT、DoH 和错误证书主机名拒绝。
- [x] 覆盖 `HTTPS`、`SVCB`、`DS`、`CAA`、`WALLET/TYPE262` 等现代 RR。
- [x] 覆盖 19 个去中心化域名插件的确定性后端契约与路由优先级。
- [x] 覆盖 denylist、sinkhole、DGA/隧道、DNS rebinding、异常 RR、放大和速率限制。
- [x] 覆盖 DNSLog 过滤、排序、分页、聚合、指标和蜜罐失败队列。

## 最早 P0-P4 计划完成度

- [x] **P0 基础环境，约 96%**：PowerDNS、运行时、管理 API、Web 管理、DNSLog、Compose、缓存、现代 RR 和一键构建均已完成；真实 DNSSEC bogus 链自动验收仍缺。
- [x] **P1 HNS，约 86%**：主链路、NXDOMAIN、缓存、审计、失败边界和 fixture 已完成；live hnsd P2P/SPV 仍为 opt-in。
- [x] **P2 插件并联，约 83%**：19 个插件、统一路由、冲突优先级、缓存隔离和契约测试已完成；真实公网链节点/API 尚未形成生产门禁。
- [x] **P3 安全防护，约 84%**：主要检测、阻断、审计、蜜罐失败队列和指标已完成；持续流量、压力和容量基线仍待补充。
- [x] **P4 文档交付，约 86%**：需求、架构、接口、安全、部署、验收和当前状态文档已齐；gpgsql 备份恢复、隔离升级回滚和 Docker 内灾备恢复已有可执行流程和自动化证据，生产全栈升级、跨主机灾备和密钥轮换演练仍待记录。
- [ ] **总体生产验收约 88%**：确定性开发和测试环境成熟，但 fixture 通过不能替代真实链后端、生产流量和灾备验收。

## 与最早计划的偏差

- [x] **开发主顺序仍遵循 P0 -> P3**，基础解析、插件并联和安全功能没有反转。
- [x] **测试门禁显著前移并扩大**，即时构建、加密/明文 DNS、19 插件和攻击样本成为统一门禁；这是范围增强。
- [x] **PowerDNS Web/Admin 被提前实施**。最早计划要求在 live HNS 和生产后端 gate 后再评估；本次按用户新目标提前完成，是明确的时间顺序偏差。
- [x] **管理界面由 anyNS Admin API 承载**，而不是修改 PowerDNS 原生 Web Server。PowerDNS 原生 Web 主要提供 API/统计，无法安全承载插件和配置扩展，因此采用统一控制面代理其 API。
- [x] **权威服务拆分为两个 backend 场景**：主管理环境用 gsqlite3 支持动态写入；最新 BIND 测试环境继续验证协议兼容。该偏差提高了可管理性和测试隔离。
- [x] **真实重型链后端后移，确定性 fixture 优先**，符合服务器资源预算，但生产真实性验收尚未完成。
- [x] **默认网络暴露更保守**，管理和测试端口仅监听回环地址，远程访问应通过受控反向代理、VPN 或 SSH tunnel。

## 后续待办

- [ ] 向 GitHub Support 提交旧 SHA 缓存对象清除请求并复核旧对象不可访问。
- [ ] 增加有效 DNSSEC 链、bogus 链、AD flag 和验证失败自动测试。
- [x] 在受控时间窗运行 live hnsd P2P/SPV 集成 smoke gate。
- [ ] 为选定插件增加真实外部 RPC/API smoke test，凭据只通过 secret 注入。
- [ ] 增加 NXDOMAIN flood、随机子域、并发、长稳和容量基线测试。
- [ ] 完成生产管理鉴权、TLS 反向代理、密钥轮换、全栈升级和跨主机灾备演练；gpgsql 本地逻辑备份恢复、隔离升级回滚与 Docker 内灾备恢复门禁已完成。
- [x] 增加独立 PostgreSQL 数据库容器部署模式，并验证 PowerDNS gpgsql 初始化、备份和恢复。
- [ ] 使用已同步 hnsd 或可控 live 名称补充正向 `NOERROR` 链上解析证据，并将其他轻量去中心化组件并入可选 Compose profile，定义 PowerDNS + 网站 + live 链解析的最低模式门禁。
