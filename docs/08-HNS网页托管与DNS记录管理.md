# HNS 网页托管与 DNS 记录管理

## 进入管理页面

1. 打开 `https://codex.viru.sh`。
2. 使用服务器单独保存的网页验收账号完成 HTTP Basic Auth。
3. 进入左侧 `PowerDNS`。

管理网页只调用 anyNS Admin API。PowerDNS API Key 保存在服务器后端，不会发送到浏览器。

## 添加 HNS 域名

1. 在 `添加托管域名` 中选择 `HNS 域名`。
2. 在 `HNS 名称` 中输入链上名称本体，例如 `example`。
   - 不要输入 `example.hns`。
   - 网页会创建 PowerDNS Zone `example.`。
3. 检查自动生成的 Nameserver，例如 `ns1.example.`。
4. 检查 Glue IPv4，当前服务器为 `68.64.179.208`。
5. 点击 `添加域名`。

创建完成后，网页会自动添加 Nameserver 的 A 记录。随后必须在持有该名称的钱包或注册平台中发布：

```text
NS     ns1.example.
GLUE4  ns1.example. 68.64.179.208
```

链上更新确认后，客户端使用 `example.hns` 通过 anyNS 私有 DoH 解析。不要向网页或服务器提交钱包私钥。

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
| A | `@` | `68.64.179.208` |
| AAAA | `@` | `2001:db8::53` |
| CNAME | `www` | `target.example.` |
| TXT | `_verify` | `verification=...` |
| MX | `@` | `10 mail.example.` |
| NS | `@` | `ns1.example.` |
| SRV | `_service._tcp` | `10 5 443 service.example.` |
| CAA | `@` | `0 issue "letsencrypt.org"` |
| HTTPS | `@` | `1 . alpn=h2,h3 ipv4hint=68.64.179.208` |
| TLSA | `_443._tcp` | `3 1 1 <certificate-sha256>` |

TXT 输入不需要手工添加最外层引号，网页保存时会按 PowerDNS 格式处理。TXT 编辑器提供 OpenAlias ETH、OpenAlias BTC 和 HNS Wallet 模板。

## 修改和删除记录

- 点击记录行右侧的编辑按钮，把现有 RRSet 加载到编辑器。
- 同一名称和类型的多条记录以多行方式编辑。
- 点击删除按钮会删除整个 RRSet。
- SOA 记录由 PowerDNS 维护，网页禁止删除。
- 未在编辑器支持列表中的原始记录类型保持只读显示，避免错误改写。

## 验证

HNS Zone 详情会显示需要发布的 `NS`、`GLUE4` 和对应的 `<name>.hns` 测试名称。

私有 DoH URL 保存在服务器：

```text
/root/anyns-public-dns/doh-credentials
```

公网 `68.64.179.208:53` 只提供权威 DNS 并拒绝递归查询。递归 ICANN 和 HNS 查询必须使用私有 DoH。
