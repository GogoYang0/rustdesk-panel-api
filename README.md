# rustdesk-panel-api

RustDesk 管理平台后端（Go 1.27）。以 [databk/rustdesk-console](https://github.com/databk/rustdesk-console) 的**端点接口与数据库契约**为兼容基准重构，不迁移任何实现代码。

## 稳定性提醒

> ⚠️ 本项目主版本号目前为 **0**（v0.x），不保证稳定性。如遇 bug 或其他影响使用的问题，欢迎提出 issue。

## 构建与运行

```sh
go build ./...   # 编译全部包
go test ./...    # 运行全部测试（含契约用例）
```

## 当前状态

- **M0 基建**（已完成）：健康检查端点、跨平台静态编译 CI（nightly / pre-release / release）、Docker 开发栈。
- **M1 后端骨架 + 认证域**（已完成）：GORM 自动迁移、JWT 有状态会话、账户/2FA/passkey/OIDC 认证域、用户资料与头像管理；**全部 23 个端点契约用例通过（openapi.yaml 双向校验）**。
- **M2 设备域 + RBAC**（已完成）：设备接入协议（heartbeat/sysinfo）、设备域与设备组、下发策略、RBAC（权限目录/角色/用户角色指派）与用户组域；全部 68 个端点契约用例通过（openapi.yaml 双向校验），路由表 ↔ openapi.yaml ↔ 授权策略档位三方一致性测试锁定（`internal/server/router_m2_policy_test.go`）。
- **M3 全量域收口**（已完成）：用户域、通讯录（含 RustDesk 客户端 legacy 兼容怪癖）、审计与仪表盘、服务器管理（经 agent 转发）、nexus 绑定与构建产物、设置域（general/smtp/ldap/frontend）、OIDC 提供者管理、更新检查；**openapi.yaml 共 164 个 operation，全部契约用例通过**。三方一致性常量 `expectedOperations = 164`（M2 收口 68 + M3 新增 96）在三方测试中强制锁定；M3 提权/跨租户安全矩阵见 `internal/qa/m3_security_test.go`。
- 契约源：`openapi.yaml`（design-first，前端 client 由同一契约生成；DTO 经 `internal/api` 生成类型 + snake_case 组装）。

## 端点清单（M1）

| 域 | 端点 | 鉴权 |
| --- | --- | --- |
| 系统 | `GET /api/healthz` | 公开 |
| 认证 | `POST /api/login`（account / sms_code / passkey_tfa 分支） | 公开 |
| 认证 | `GET /api/login-options` | 公开 |
| 认证 | `POST /api/currentUser` | JWT |
| 认证 | `GET /api/sessions` · `DELETE /api/sessions/{jti}` | JWT |
| 认证 | `POST /api/logout` | JWT |
| 认证 | `POST /api/2fa/setup` · `POST /api/2fa/verify` · `DELETE /api/2fa` | JWT |
| 认证 | `POST /api/passkey/register/begin` · `/verify` · `GET /api/passkey/list` | JWT |
| 认证 | `POST /api/passkey/auth/begin` · `/verify` | 公开 |
| 认证 | `POST /api/oidc/auth` · `GET /api/oidc/callback` · `GET /api/oidc/auth-query` | 公开 |
| 用户 | `PATCH /api/users/me`（display_name / email / note） | JWT |
| 用户 | `PATCH /api/users/me/password`（bcrypt 复核旧密码） | JWT |
| 用户 | `POST /api/users/me/avatar` · `DELETE /api/users/me/avatar`（webp ≤2MB） | JWT |
| 用户 | `GET /api/avatars/{filename}`（静态服务，防路径穿越） | 公开 |

安全基线：JWT 有状态会话（`login_sessions` 可撤销）、限流 per-IP per-route（login 5/min、password 5/min、avatar 10/min、静态头像 60/min）、敏感列（password/verifier/totp secret）显式加载、错误包络对齐 NestJS 三形态。

## 端点清单（M2）

| 域 | 端点 | 授权 |
| --- | --- | --- |
| 设备协议 | `POST /api/heartbeat` · `POST /api/sysinfo` | 公开（设备维度限流 10/5 次每分钟，tracker=id→uuid→IP） |
| 设备 | `GET /api/peers` | JWT（handler 内状态复核） |
| 设备 | `GET /api/devices` · `PATCH /api/devices/status` · `PATCH /api/devices/{guid}` · `DELETE /api/devices/{guid}` · `POST /api/devices/{uuid}/disconnect` | `devices.*` 权限码 |
| 设备组 | `GET /api/device-group/accessible` | JWT（handler 内状态复核） |
| 设备组 | `GET/POST /api/device-groups` · `PATCH/DELETE/POST /api/device-groups/{guid}` · `DELETE /api/device-groups/{guid}/devices` | AdminGuard |
| 设备组 | `GET /api/device-groups/strategy-targets` | `strategies.assign` |
| 策略 | `GET/POST /api/strategies` · `GET/PATCH/DELETE /api/strategies/{guid}` | `strategies.view/create/edit/delete` |
| 策略 | `GET /api/strategies/candidates` · `GET /api/strategies/target-candidates` · `GET /api/strategies/{guid}/assignments` · `POST /api/strategies/{guid}/assign` · `POST /api/strategies/{guid}/unassign` | `strategies.assign` |
| RBAC | `GET /api/permissions` · `GET /api/roles` · `GET /api/roles/{guid}` | `roles.view` |
| RBAC | `POST /api/roles` · `PATCH /api/roles/{guid}` · `DELETE /api/roles/{guid}` · `GET /api/roles/{guid}/protection-impact` | super administrator |
| RBAC | `GET/PUT /api/users/{guid}/roles` · `GET /api/users/{guid}/roles/eligibility` | `roles.assign` |
| RBAC | `GET /api/permissions/me` | JWT |
| 用户组 | `GET/POST /api/user-groups` · `PUT/DELETE /api/user-groups/{guid}` · `GET /api/user-groups/{guid}/users` · `POST /api/user-groups/{guid}/users` | `user_groups.*`（成员移动 `user_groups.membership`） |

M2 安全基线：36 个权限码（33 可分配 + `roles.create/edit/delete` 仅系统内置角色）；Perm 路由按用户角色作用域（global / device_group）查库决策、资源级复核在服务层；保护账号与超管防护链（自改拦截、保护角色指派需确认、默认用户组不可删、超管角色变更仅超管可操作）；全部 403 与越权尝试写入 denied 审计。路由授权档位（public / auth / perm / admin_guard / super_admin）由 `Router.Routes()` 暴露，并与 openapi security、设计 §1.6 经三方一致性测试锁定。

## 端点清单（M3）

M3 新增 96 条路由，全量 164 个 operation。档位分布（`internal/qa/m3_security_test.go` 断言）：
**public 19 · auth 53 · perm 62 · admin_guard 23 · super_admin 7**。

| 域 | 端点 | 授权 |
| --- | --- | --- |
| 用户 | `GET/POST /api/users` · `POST /api/users/invite` · `PATCH /api/users/batch/status` · `PATCH /api/users/batch/security` · `DELETE /api/users/batch/sessions` · `GET/PATCH/DELETE /api/users/{guid}` · `PATCH /api/users/{guid}/security` · `DELETE /api/users/{guid}/sessions` · `GET /api/admin/users` | `users.*` 权限码（`PATCH /api/users/{guid}` 按字段分权，仅 JWT） |
| 用户 | `POST /api/invitations/verify` · `POST /api/invitations/accept` | 公开 |
| 通讯录 | `GET/POST /api/ab` · `POST /api/ab/settings` · `GET/POST /api/ab/personal` · `GET /api/ab/custom/profiles` · `POST /api/ab/custom/add` · `PUT /api/ab/custom/update/profile` · `DELETE /api/ab/custom` · `GET/POST /api/ab/shared/profiles` · `GET /api/ab/shared/list` · `GET /api/ab/shared/{guid}/access` · `GET/POST /api/ab/peers` · `GET/POST /api/ab/tags/{guid}` · peer/tag 增删改 6 条 | JWT（owner/规则并集在服务层复核） |
| 通讯录 | `GET /api/ab/shared/{guid}/share-candidates` · `POST /api/ab/shared/add` · `POST/PATCH/DELETE /api/ab/rule(s)` | `address_books.share` |
| 通讯录 | `PUT /api/ab/shared/update/profile` · `DELETE /api/ab/shared` | `address_books.edit` |
| 通讯录 | `GET /api/ab/rules` | `address_books.view` |
| 审计 | `POST /api/audit/conn` · `POST /api/audit/file` · `POST /api/audit/alarm` | 公开（per-IP 50/min，RustDesk 客户端上报） |
| 审计 | `GET /api/audits/conn` · `GET /api/audits/file` · `GET /api/audits/alarm` · `GET /api/audits/console` | `audit.view` |
| 审计 | `GET /api/audits/conn/active` | `devices.disconnect`（scope ∩ active 逐行判定） |
| 审计 | `PATCH /api/audits/conn/{id}` | super administrator |
| 仪表盘 | `GET /api/dashboard` · `GET /api/dashboard/trends` | super administrator |
| 服务器 | `GET /api/servers` · `GET /api/servers/{node}/peers` · `GET /api/servers/{node}/sessions` · `GET /api/servers/{node}/services/{service}/logs` | `servers.view` |
| 服务器 | `DELETE /api/servers/{node}/sessions/{uuid}` | `servers.disconnect` |
| 服务器 | `GET/PUT /api/servers/{node}/services/{service}/config` | `servers.config` |
| 服务器 | `POST /api/servers/{node}/services/{service}/{action}` | `servers.control` |
| 服务器 | `GET/PUT /api/servers/{node}/bans` | `servers.ban` |
| nexus | 绑定 4 条（`auth/login`、`auth/status`、`auth/bind-status`、`auth/bind`） | JWT |
| nexus | `POST/GET /api/nexus/builds` · `DELETE /api/nexus/builds/{uuid}` · `GET /api/nexus/builds/{uuid}/files` · `GET /api/nexus/builds/{uuid}/files/{filename}` | JWT（构建归属用户校验在服务层） |
| 设置 | `GET /api/settings/frontend` | 公开 |
| 设置 | `GET/PUT /api/settings/general` · `GET/PUT /api/settings/smtp` · `GET/PUT /api/settings/ldap` | AdminGuard |
| 设置 | `POST /api/settings/smtp/test` · `POST /api/settings/ldap/test` | AdminGuard（5/min） |
| OIDC 提供者 | `GET/POST /api/oidc-providers` · `PATCH /api/oidc-providers/sort` · `GET/PATCH/DELETE /api/oidc-providers/{guid}` · `PATCH /api/oidc-providers/{guid}/toggle` · `POST /api/oidc-providers/{guid}/test` | AdminGuard |
| 更新检查 | `GET /api/update-check` | AdminGuard（恒 200，上游不可达时降级为零更新结果） |
| 静态 | `GET /`（SPA 兜底） · `GET /files/{path}`（nexus 产物） | 公开（safeJoin 防穿越） |

M3 安全基线：

- **状态码特例**：`POST /api/nexus/builds` = **201**；`DELETE /api/nexus/builds/{uuid}` = **204**。
- **服务器域错误映射矩阵**（经 agent 转发，逐字节固定）：网络错误 503 `Server node unavailable`、上游 400/载荷违例 400 `Invalid server management request`、上游 404 404 `Server resource not found`、上游 409 → 400 `Server configuration conflicts`、上游 504 504 `Server management operation timed out`、其他 5xx 502 `Server management operation failed`、非 JSON object 502 `Invalid node management response`。
- **敏感列掩码**：settings smtp `pass` / ldap `bindCredentials` 回读恒 `******`，PUT 命中掩码即跳过更新（防误清空）；响应体字节级不含明文。
- **运行时设置驱动**：JWT 有效期天数、WebAuthn RP、OIDC 提供者三级读取（`system_settings` 表 → env fallback → 内置缺省），OIDC 表为空时降级使用 `OIDC_*` env。
- **路径安全**：nexus 产物文件名白名单 `^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`（首字符 alnum 排除 `.`/`..`）+ `SafeJoin` 纵深防御；`/files` 与之共用同一安全语义，穿越族一律 400 `Invalid path`。
- **跨租户隔离**：nexus 构建的取消/产物清单/产物下载对非归属者一律 404（不泄漏资源存在性）。
- **RustDesk 客户端 legacy 兼容怪癖**（字节级锁定，`internal/qa/m3_compat_test.go`）：`GET /api/ab` 空数据返回裸 `null`（4 字节）；`POST /api/ab` 失败返回 `{error:msg}` 但 HTTP 仍 200；`POST /api/ab/settings` 恒 `{max_peer_one_ab:0}`；`GET /api/ab` 非空为双重 JSON 编码（`data` 为字符串内嵌 JSON，其内 `tag_colors` 再嵌一层）。
- **通知渠道**：`GET /api/update-check` 与 OIDC/LDAP/SMTP connectivity test **恒返回 200**，连通失败以响应体 `success:false` 表达。

## 本地开发

```sh
# SQLite 快速启动
HTTP_ADDR=:8080 go run ./cmd/api

# MySQL 开发栈（env 见 docker-compose.yml）
docker compose up -d --build

# 验证
curl http://localhost:8080/api/healthz
# M3 公开端点（无需 JWT）
curl http://localhost:8080/api/settings/frontend

# 测试（SQLite 内存库，CGO_ENABLED=0 可跑）
CGO_ENABLED=0 go test ./...

# 契约 + 三方一致性（路由表 ↔ openapi.yaml ↔ 设计策略档位）
CGO_ENABLED=0 go test ./internal/contract/ ./internal/server/ ./internal/qa/
```

## 配置

全部通过环境变量注入（`internal/config/config.go`）。

**基础**

| 环境变量 | 缺省 | 说明 |
| --- | --- | --- |
| `HTTP_ADDR` | `:8080` | HTTP 监听地址 |
| `DB_DRIVER` | `sqlite` | `mysql` \| `sqlite`（启动期校验） |
| `DB_DSN` | `./rustdesk-panel.db` | MySQL 建议 `parseTime=true&loc=Local` |
| `JWT_SECRET` | 开发缺省 | **生产必须覆盖**（命中缺省启动打 WARNING） |
| `JWT_EXPIRY_DAYS` | `30` | 初始缺省；运行期由 `general.jwtExpiryDays` 覆盖 |
| `DATA_DIR` | `./data` | 静态文件根（头像 `avatars/`；nexus 产物 `nexus/`） |
| `ADMIN_USERNAME` / `ADMIN_EMAIL` / `ADMIN_PASSWORD` | `databk` / `databk@github.com` / `databk` | 管理员种子 |
| `RATE_LIMIT_ENABLED` | `true` | per-IP per-route 限流开关 |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `APP_VERSION` | `0.3.0` | 版本号（update-check 遥测 `current` 值） |

**WebAuthn**（M3 起降级为 fallback，库值 `general.webauthn*` 优先）

| 环境变量 | 缺省 |
| --- | --- |
| `WEBAUTHN_RP_ID` | `localhost` |
| `WEBAUTHN_ORIGINS` | `http://localhost:8080`（逗号分隔） |

**M3 域**

| 环境变量 | 缺省 | 说明 |
| --- | --- | --- |
| `RUSTDESK_NODES` | 空 | 中继节点清单 JSON `[{id,name,url,token}]`。空串=无节点；**启动期 fail-fast 校验**：JSON 合法性、id 唯一且匹配正则、url 纯 http(s) origin（禁 path/query/fragment）、token ≥32 字符、name ≤100、≤100 节点 |
| `NEXUS_UPSTREAM` | `https://api.databk.top` | nexus 代理与 update-check 上游 |
| `UPDATE_CHANNEL` | `stable` | `stable` \| `nightly`（启动期校验） |
| `OIDC_ISSUER` | 空 | oidc_providers 表无 enabled 记录时的 env fallback；空即视为未配置 |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` / `OIDC_SCOPE` | 空 | 同上（scope 空时按 provider type 取缺省） |

示例：

```sh
RUSTDESK_NODES='[{"id":"node-a","name":"Alpha","url":"http://10.0.0.1:21114","token":"<32+ 字符>"}]' \
  HTTP_ADDR=:8080 go run ./cmd/api
```

### 运行期可调设置（`system_settings` 表，经 `/api/settings/*` 管理）

`general.watermarkEnabled`、`general.defaultLanguage`（缺省 `zh-CN`）、`general.jwtExpiryDays`（缺省 30）、`general.auditRetentionDays`（缺省 90）、`general.siteFrontendUrl`、`general.siteBackendUrl`、`general.webauthnEnabled`、`general.webauthnRpName`；smtp 7 键、ldap 14 键。敏感键（`smtp.pass`、`ldap.bindCredentials`）回读恒 `******`。

## 静态资源与产物服务

- `GET /` SPA 兜底：`internal/static/dist` 经 `embed` 打包（排除 `/api`、`/files`、`/avatars`）。
- `GET /files/{path}`：服务 `DATA_DIR/nexus` 下 nexus 构建产物，经 safeJoin（含 `..` 逃逸即 400 `Invalid path`）。
- `GET /api/nexus/builds/{uuid}/files/{filename}`：需 JWT 且构建归属当前用户；文件名经白名单正则前置过滤。

静态资源通过 `internal/static/static.go` 的 `embed.FS` 编译进二进制，无外部运行时依赖。

## 构建产物命名

```
rustdesk-panel-api_<version>_<os>_<arch>.tar.gz   # windows 为 .zip
rustdesk-panel-api_1.2.0_linux_amd64.tar.gz       # release
rustdesk-panel-api_1.2.0-rc.1_darwin_arm64.tar.gz # pre-release
rustdesk-panel-api_0.0.0-nightly.20261008_linux_amd64.tar.gz  # nightly
```

## 分支模型

classic gitflow（main/develop + feature/release/hotfix），规范定义见 `.gitflow/workflow.json`。提交遵循 Conventional Commits。
