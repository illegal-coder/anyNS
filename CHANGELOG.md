# Changelog

## 2026-06-15

- 新增 DS、DNSKEY、TLSA、CAA、NS 校验与规范化，以及 DNSKEY 到 DS 推导。
- 新增 PowerDNS DNSSEC cryptokey API/UI 和 gpgsql 部署、初始化、备份恢复门禁。
- 新增 HNS DNS wire 支持与 Unicode/IDNA 管理流程。
- 新增带 SSRF、重定向、sender、响应大小和递归限制的 EIP-3668 CCIP-Read。
- 新增 ACME DNS-01 状态机、幂等、持久化、续期、吊销、TLSA 发布和 `0600` 私钥存储。
- 新增细粒度管理 scope、capability-aware Admin UI、嵌入式 UI handler 和 Selenium 回归。
- 保持最低 Go 版本为 1.18；使用 `x/net v0.19.0`、`x/crypto v0.17.0` 和 `x/text v0.14.0`，避免 `x/crypto v0.31.0` 的 Go 1.20 要求。
- 最终合并回归通过 Go 全量测试/vet、配置检查、前端测试/ESLint/构建、Compose 渲染、gpgsql 恢复、Selenium 和 Pebble 证书侧载。
