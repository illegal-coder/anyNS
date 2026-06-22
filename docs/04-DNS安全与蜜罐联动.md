# DNS 安全与蜜罐联动需求

## 1. 安全目标

anyNS 必须在 PowerDNS 主链路上提供 DNS 攻击检测、拦截、DNSLog 审计和蜜罐联动能力。CoreDNS 仅作为可选增强层，用于补充已有 CoreDNS 安全插件或边缘防护策略。

## 2. 检测范围

必须覆盖：

- DNS tunneling。
- DGA 域名。
- 高熵域名。
- NXDOMAIN flood。
- 随机子域攻击。
- DNS rebinding。
- 异常 RR 查询。
- 反射放大滥用。
- 黑白名单。
- Sinkhole。
- 速率限制。
- 风险评分。

## 3. 风险评分

输入特征：

- qname 长度。
- label 数量。
- 字符熵。
- 数字和特殊字符比例。
- qtype 异常性。
- NXDOMAIN 比例。
- 客户端查询速率。
- 域名新鲜度。
- 命中黑白名单。
- 是否命中去中心化插件。

输出风险等级：

- `none`
- `low`
- `medium`
- `high`
- `critical`

## 4. 拦截动作

支持动作：

- `allow`
- `log_only`
- `block`
- `sinkhole`
- `rate_limit`
- `forward_to_honeypot`
- `tag_and_continue`

动作必须可按租户、客户端视图、规则和插件配置。

## 5. DNSLog 生成

所有安全事件必须生成 DNSLog，包含：

- 时间。
- trace id。
- 客户端 IP。
- qname。
- qtype。
- rcode。
- 响应摘要。
- 命中规则。
- 风险等级。
- 动作。
- 插件来源。
- 原始记录。
- 延迟。

## 6. 蜜罐联动

投递方式：

- 通用 Webhook。
- HTTP API。
- 批量事件投递。

安全要求：

- API Key。
- HMAC 签名。
- TLS。
- 幂等键。
- 请求超时。
- 失败重试。
- 失败队列。

适配器预留：

- HFish。
- T-Pot。
- Cowrie。
- 自定义企业蜜罐。

## 7. 可观测性

必须提供：

- 拦截总数。
- 各风险等级数量。
- 各规则命中数。
- 前 N 个客户端。
- 前 N 个 qname。
- 蜜罐投递成功率。
- 蜜罐投递延迟。
- 失败队列长度。

## 8. 验收场景

- TXT 长 payload 触发 DNS tunneling 风险。
- 高熵随机域名触发 DGA 风险。
- 大量不存在子域触发 NXDOMAIN flood。
- 私网地址响应触发 DNS rebinding 风险。
- 异常 qtype 高频查询触发拦截。
- 命中高风险规则后事件成功投递蜜罐 API。
- 蜜罐 API 不可用时进入失败队列并重试。

## 9. DNSSEC、DANE、ACME 与 CCIP 安全边界

- 只有验证结果为 secure 的 DNSSEC 链，才能把 TLSA 当作 DANE 信任输入；无 DS、bogus 链和未验证响应不得静默降级为“已验证”。
- PowerDNS API key 可修改 DNS-01 challenge、DS、CAA 和 TLSA，必须按高权限密钥隔离、轮换和脱敏。
- ACME 作业使用幂等键、有限重试、超时和 `0600` 私钥文件；API 永不返回私钥。
- CCIP-Read 必须校验 `OffchainLookup.sender`，限制 URL scheme、目标网络和响应大小；最终网关签名/证明由 resolver callback 合约验证。
- EIP-712 只有在明确 chain ID、verifying contract、type hash、nonce 和 expiry 后才能接入；当前项目不接受未定义域的通用 Web3 签名证明。

## 10. CI 源码策略门禁

GitHub Actions 的 `CI` workflow 会运行 `anyns-source-policy`，并把 Markdown 摘要写入 workflow step summary 与短期 artifact。该门禁只使用仓库内无密钥源码和 fixture，覆盖以下确定性策略：

- GitHub Actions 第三方 Action 必须固定到 40 位 commit SHA，workflow 权限不得请求 `write-all` 或常见写 scope。
- 跟踪文件不得包含 PEM 私钥块、私有自动化路径或 Codex 运行目录。
- shell 脚本不得把 `curl`/`wget` 下载内容直接管道给 `sh`/`bash`。
- Compose/YAML 不得启用 `privileged`、host network、host pid 或 host ipc。
- Go 源码不得导入 `crypto/md5`、`crypto/sha1`，不得设置 `InsecureSkipVerify:true`，不得通过 `exec.Command("sh"|"bash", "-c", ...)` 构造 shell 命令。

该扫描器带有 true positive、safe example 和 false-positive 边界测试。它是高信号源码策略补充，不能证明不存在业务逻辑漏洞、运行时 SSRF、凭据误配置或隔离环境中的链路问题；live hnsd、Pebble、Selenium、灾备、外部 RPC/API 与 destructive/load 类检查仍必须留在服务器隔离门禁。

详细威胁模型见 [09-去中心化验证与证书运维.md](./09-去中心化验证与证书运维.md)。
