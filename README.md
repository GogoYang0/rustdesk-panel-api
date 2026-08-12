# rustdesk-panel-api

RustDesk 管理平台后端（Go 1.27）。以 [databk/rustdesk-console](https://github.com/databk/rustdesk-console) 的**端点接口与数据库契约**为兼容基准重构，不迁移任何实现代码。

## 当前状态

- **M0 基建**（已完成）：健康检查端点、跨平台静态编译 CI（nightly / pre-release / release）、Docker 开发栈。
- **M1 后端骨架 + 认证域**（已完成）：GORM 自动迁移、JWT 有状态会话、账户/2FA/passkey/OIDC 认证域、用户资料与头像管理；**全部 23 个端点契约用例通过（openapi.yaml 双向校验）**。
- **M2 设备域 + RBAC**（已完成）：设备接入协议（heartbeat/sysinfo）、设备域与设备组、下发策略、RBAC（权限目录/角色/用户角色指派）与用户组域；**全部 68 个端点契约用例通过（openapi.yaml 双向校验）**，路由表 ↔ openapi.yaml ↔ 授权策略档位三方一致性测试锁定（`internal/server/router_m2_policy_test.go`）。
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

## 本地开发

```sh
# SQLite 快速启动
HTTP_ADDR=:8080 go run ./cmd/api

# MySQL 开发栈（env 见 docker-compose.yml）
docker compose up -d --build

# 验证
curl http://localhost:8080/api/healthz

# 测试（SQLite 内存库，CGO_ENABLED=0 可跑）
CGO_ENABLED=0 go test ./...
```

## 配置

全部通过环境变量注入（`internal/config/config.go`）：`HTTP_ADDR`、`DB_DRIVER`(mysql|sqlite)、`DB_DSN`、`JWT_SECRET`、`JWT_EXPIRY_DAYS`、`DATA_DIR`（头像存储根）、`WEBAUTHN_RP_ID`、`WEBAUTHN_ORIGINS`、`ADMIN_USERNAME/EMAIL/PASSWORD`（管理员种子）、`RATE_LIMIT_ENABLED`、`LOG_LEVEL`。生产部署必须覆盖 `JWT_SECRET`（缺省值启动打 WARNING）。

## 构建产物命名

```
rustdesk-panel-api_<version>_<os>_<arch>.tar.gz   # windows 为 .zip
rustdesk-panel-api_1.2.0_linux_amd64.tar.gz       # release
rustdesk-panel-api_1.2.0-rc.1_darwin_arm64.tar.gz # pre-release
rustdesk-panel-api_0.0.0-nightly.20261008_linux_amd64.tar.gz  # nightly
```

## 分支模型

classic gitflow（main/develop + feature/release/hotfix），规范定义见 `.gitflow/workflow.json`。提交遵循 Conventional Commits。
