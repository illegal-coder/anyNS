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
