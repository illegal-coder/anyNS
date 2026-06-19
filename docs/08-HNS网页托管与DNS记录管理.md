# HNS 网页托管与 DNS 记录管理

## 进入管理页面

1. 打开部署后的管理站点，例如 `https://admin.example.org`。
2. 使用服务器单独保存的网页验收账号完成 HTTP Basic Auth。
3. 进入左侧 `PowerDNS`。

管理网页只调用 anyNS Admin API。PowerDNS API Key 保存在服务器后端，不会发送到浏览器。

## 添加 HNS 域名

1. 在 `添加托管域名` 中选择 `HNS 域名`。
2. 在 `HNS 名称` 中输入链上名称本体，例如 `example`。
   - 可以粘贴 `example.hns` 或 `example.hsd`，网页和 API 会去掉显示后缀。
   - PowerDNS Zone 主键始终是真实单标签顶级区，例如 `example.`。
   - 不要把 `www.example` 这类子域当作 HNS 托管 Zone 创建；子域应作为记录写入 `example.`。
3. 检查自动生成的 Nameserver，例如 `ns1.example.`。
4. 检查 Glue IPv4，并填写实际权威 DNS 公网地址；文档示例使用 `192.0.2.53`。
5. 点击 `添加域名`。

创建完成后，网页会自动添加 Nameserver 的 A 记录。随后必须在持有该名称的钱包或注册平台中发布：

```text
NS     ns1.example.
GLUE4  ns1.example. 192.0.2.53
```

链上更新确认后，客户端可以使用 `example.hns` 或 `example.hsd` 作为面向用户的
显示/输入别名。anyNS 在写入 PowerDNS 和查询 hnsd 风格后端时会转换为真实顶级
名称 `example.`；`.hns` 不是公开 DNS 中的父 Zone。不要向网页或服务器提交钱包私钥。

## 管理 DNS 记录

1. 在 `托管域名` 表格中找到 Zone。
2. 点击 `管理记录`。
3. 使用搜索框或记录类型筛选器定位记录。
4. 在右侧 `添加 DNS 记录` 中选择类型、名称、TTL 和内容。
5. 点击 `保存记录`。

名称填写规则：

- `@`：Zone 根域名。
- `www`：自动转换为 `www.<zone>.`。
- 完整域名：可以直接填写以点结尾的 FQDN。

常用记录示例：

| 类型 | 名称 | 内容示例 |
| --- | --- | --- |
| A | `@` | `192.0.2.53` |
| AAAA | `@` | `2001:db8::53` |
| CNAME | `www` | `target.example.` |
| TXT | `_verify` | `verification=...` |
| MX | `@` | `10 mail.example.` |
| NS | `@` | `ns1.example.` |
| SRV | `_service._tcp` | `10 5 443 service.example.` |
| CAA | `@` | `0 issue "letsencrypt.org"` |
| HTTPS | `@` | `1 . alpn=h2,h3 ipv4hint=192.0.2.53` |
| TLSA | `_443._tcp` | `3 1 1 <certificate-sha256>` |

TXT 输入不需要手工添加最外层引号，网页保存时会按 PowerDNS 格式处理。TXT 编辑器提供 OpenAlias ETH、OpenAlias BTC 和 HNS Wallet 模板。

## 修改和删除记录

- 点击记录行右侧的编辑按钮，把现有 RRSet 加载到编辑器。
- 同一名称和类型的多条记录以多行方式编辑。
- 点击删除按钮会删除整个 RRSet。
- SOA 记录由 PowerDNS 维护，网页禁止删除。
- 未在编辑器支持列表中的原始记录类型保持只读显示，避免错误改写。

## 验证与访问边界

HNS Zone 详情会显示需要发布的 `NS`、`GLUE4` 和对应的 `<name>.hns` 测试名称。
权威 DNS 查询应直接验证单标签顶级区：

```bash
AUTH_DNS="192.0.2.53"
dig @"$AUTH_DNS" example. SOA
dig @"$AUTH_DNS" example. NS
dig @"$AUTH_DNS" ns1.example. A
```

私有 DoH 地址和访问凭据由部署方通过受控渠道交付，必须保存在仓库和公开文档
之外。本文不记录服务器本地凭据路径、反向代理拓扑或任何密钥位置。

```text
https://<private-doh-endpoint>/dns-query
```

公网权威地址的 `53/udp` 和 `53/tcp` 只提供权威 DNS 并拒绝递归查询。递归 ICANN 和 HNS 查询必须使用受控递归服务或私有 DoH。

自动化证据：

- `bash tests/acceptance/docker-soa-tld.sh` 验证 `example.hns` 创建后实际
  PowerDNS Zone 为 `example.`，Unicode `灵.hns` 存储为 `xn--5nx.` 并保留
  `unicode_name`，非法子 Zone `www.example` 返回 `400`，Authoritative 和
  Recursor 均能返回一致的 SOA/NS/glue，SOA serial 在记录更新后递增。
