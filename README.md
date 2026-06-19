# anyNS

anyNS 是基于 PowerDNS 的去中心化名称解析、DNS 安全和管理平台。当前实现同时覆盖传统 DNS、HNS、DNSSEC/DANE、EIP-3668 CCIP-Read、使用 PowerDNS DNS-01 的 ACME 证书生命周期，以及显式 opt-in 的私有根 CA 签发模式。

## 快速验证

```bash
GOTOOLCHAIN=local GOMAXPROCS=1 go test -p=1 ./...
GOTOOLCHAIN=local GOMAXPROCS=1 go vet -p=1 ./...
bash tests/acceptance/check-local.sh

cd web/admin
npm ci
npm test
npm run check
npm run build
```

隔离 Docker 验收：

```bash
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/docker-gpgsql-backup-restore.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/selenium-admin.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/decentralized-certificates.sh
COMPOSE_PARALLEL_LIMIT=1 bash tests/acceptance/private-ca-certificates.sh
```

证书验收只使用回环端口、独立 Compose project、测试区、Pebble 测试 CA 或测试私有根 CA。生产配置、真实密钥和生产数据不得放入仓库。

## 文档

- [接口与数据模型](docs/03-接口与数据模型.md)
- [部署与对接流程](docs/05-部署与对接流程.md)
- [HNS 网页托管与 DNS 记录管理](docs/08-HNS网页托管与DNS记录管理.md)
- [去中心化验证与证书运维](docs/09-去中心化验证与证书运维.md)
- [变更记录](CHANGELOG.md)

仓库最低 Go 版本保持 `1.18`。依赖必须能由 Go 1.18/gccgo 解析和构建，不能通过本地升级工具链掩盖兼容问题。
