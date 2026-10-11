# verdantflare-app-network

VerdantFlare AppCenter 网络出口应用，版本 `0.1.0`。Dashboard 与 Go 业务服务同容器交付，前端仅消费 AppSDK 1.1，不包含 Studio 私有组件或 Wails bindings。

## 1. 实现入口

- `frontend/`：代理列表、详情、CRUD、固定目标检测、批量检测、脱敏导入导出、国旗及来源画像；保留原 H1 行为。
- `internal/egress/`：代理配置、AES-GCM 凭据、revision 并发控制、探测租约、固定目标与端点防护。
- `internal/identity/`：每次调用 Core 的应用授权端口；禁止把调用方提交的身份 Header 直接当作业务权限。
- `internal/transport/`：应用 HTTP 和内部 Dashboard 制品读取。
- `migrations/`：独立 `network` Schema、同事务业务审计和默认关闭的数据库写门。`serve` 只校验 Schema；建表必须显式运行 `network migrate`。
- `internal/handoff/`：受控源冻结、只读快照、原 AAD 校验、事务导入和激活前核对；不挂载 HTTP 路由。

产品、鉴权与迁移事实源位于设计仓库：[预装应用设计](https://github.com/verdantflarehub/verdantflare-design/blob/dev/changes/change_20261011_preinstalled_apps.md)、[应用访问契约](https://github.com/verdantflarehub/verdantflare-design/blob/dev/docs/design/contracts/preinstalled-app-access-v1.md)、[AppDashboard 契约](https://github.com/verdantflarehub/verdantflare-design/blob/dev/docs/design/contracts/app-dashboard-v1.md)。真实应用指派与消费者闭环 H2 不属于本次迁移。

## 2. 受控配置

服务进程读取以下环境变量，凭据由部署环境的 Secret 提供：

- `NETWORK_DATABASE_URL`：Network 数据库连接；运行账号只获代理表和新审计所需权限，不得是 Schema／表所有者、超级用户，或拥有写门、接管记录、历史审计的修改权限。显式迁移命令使用独立 Schema 所有者。
- `NETWORK_STATION_ID`：固定 Station 身份，必须与数据库和 Core 响应一致。
- `NETWORK_ENCRYPTION_KEY`：Base64 编码的 32 字节 AES 密钥；导入既有记录时保留原受控密钥，不生成新密钥覆盖旧密文。
- `NETWORK_ALLOWED_INTERNAL`：精确允许的内部代理 `host:port` 列表，逗号分隔；缺省拒绝内部地址，不包含代理管理端口。
- `NETWORK_CORE_URL`、`NETWORK_CORE_TOKEN`：Core 内部地址和专属应用服务凭据。
- `NETWORK_STUDIO_TOKEN`：Studio 访问本应用的专属服务凭据。
- `NETWORK_DASHBOARD_DIR`：默认 `/app/dashboard`；启动时校验版本、摘要及全部资源字节。
- `NETWORK_LISTEN_ADDR`：默认 `:8080`。

凭据不通过页面配置、URL 查询参数或业务错误返回。服务仅供受控内部访问；不提供独立公网 MCP。

## 3. 构建与检查

`release` 分支的 Actions 构建前端、Go 二进制和容器，发布不可覆盖的 `network-v0.1.0` 镜像。Dockerfile 使用独立前端构建阶段，镜像不含 Node、编译器或源码工具。

允许的本机纯单元／静态检查：

```text
go test ./...
go vet ./...
cd frontend
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm test
```

协议连通与数据库用例带 `integration` 构建标记，只在 5090 dev 执行；`NETWORK_TEST_DATABASE_URL` 指向允许创建临时测试数据库的受控配置。测试仅创建 `network_test_*` 独立库并清理，不能指向已有业务库作替代清理。入口为 `go test -tags integration ./...`；它会启动测试协议监听器，禁止在本机执行。单元和编译通过不等于已发布、数据库迁移或 Wails 验收。

## 4. 切换准备

迁移命令及参数、冻结证据、恢复顺序以中央[Network H1 接管变更](https://github.com/verdantflarehub/verdantflare-design/blob/dev/changes/change_20261011_network_h1_handoff.md)为事实源。现有环境使用 `handoff-freeze-source → handoff-export → handoff-verify → handoff-check → handoff-import → handoff-activate`；目标 Schema 先显式 `migrate`。归档、原密钥、迁移 ID 与两个数据库连接均来自受控配置，不把归档交给 Dashboard 或 Git。

源冻结是独立的显式管理操作；后续源访问均为只读。导出保留全部代理字段、已到期 probe token／lease 与 `egress.*` 审计，原 AAD 不变。导入拒绝未冻结源、未结束 lease、源变化和非空目标冲突；同批重试逐项校验，不覆盖。目标导入后为 `staged`，服务与探测不能写入；切换前再验证源与目标才可 `handoff-activate`。

仅全新空环境使用 `migrate → activate-fresh`。显式 `handoff-close` 关闭目标写门；它不自动恢复 Core 写方。有新写入或探测结果后必须对账并另行处理增量，不能只切镜像回退。

新事务审计归 `network.audit_events`；源历史保留，完整接管副本归 `network.legacy_audit_events` 并绑定迁移 ID。跨服务授权证明本次请求开始时的权限，未宣称持有 Core 锁直到 Network SQL 提交。迁移命令已有纯单元与集成测试入口；数据库触发器、角色、事务锁及真实数据交接尚须 5090 验证。
