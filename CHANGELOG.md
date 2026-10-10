# 更新日志（Changelog）

本项目的所有重要变更将记录在本文件中。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 简化版。

## v0.2.0（2026-10-11）

### 新增

- **[feature] 设备个人归属**：`PATCH /api/devices/{guid}/assign`（新权限码 `devices.assign`，device_group 档，requires devices.view+users.view）——分配/转移/解绑单属主（复用 `peers.userGuid`，解绑=空载荷置 NULL），console_audits 以 `device.assign`/`device.unassign` 留痕；`GET /api/users/me/devices`（登录即用，精简 MyDeviceView）与 `GET /api/users/{guid}/devices`（users.view 只读反查）；删除用户时应用层事务级联清空其名下设备归属。兼容说明：既有 `PATCH /api/devices/{guid}` 的 `userName` 路径原样保留（超管档），assign 为推荐写入口。
- **[feature] 强制 MFA 策略 + 登录二次验证审计**：`mfa.enforceGlobal` / `mfa.enforceUserGroupGuids` 两键（system_settings category=mfa）+ `GET/PUT /api/settings/mfa`（管理员档）；password / passkey 免密 / OIDC 三登录收敛点统一执行强制判定（已有 TOTP 或 passkey-2FA 视为满足，owner/管理员不豁免）；`LoginResponse.type` 新增 `mfa_enroll` 分支 + 公开绑定双端点 `POST /api/auth/mfa/enroll`、`/api/auth/mfa/enroll/verify`（10 分钟步会话，pending TOTP 存 login_sessions.code）；新表 `login_audits`（迁移 `000004_m4_gap2`，双方言）best-effort 记录登录六态并纳入 `general.auditRetentionDays` 清理；查询端 `GET /api/audits/login`（audit.view）。

### 变更

- openapi.yaml 契约 164 → **172 operation**（137 path），版本 1.2.0；`LoginResponse.type` 枚举追加 `mfa_enroll`。
- RBAC 权限目录 36 → **37 码**（`devices.assign`）。

### 兼容性

- 官方 RustDesk 客户端：`mfa_enroll` 分支不返回 access_token，客户端按既有判定（type==access_token 且 token 非空）视为"未完成登录"，不受影响；被强制用户请使用 Web 控制台完成 TOTP 绑定。
- `access_token` / `email_check` / `account` 既有语义未做任何改动。
- 数据库迁移 `000004_m4_gap2` 仅新增 `login_audits` 表，无既有表结构变更。

## v0.1.1（2026-10-10）

### 修复

- **[fix] 官方客户端登录 type 兼容**：成功登录响应 `type` 由自造值 `account` 改为 `access_token`，对齐官方 RustDesk 客户端（flutter `user_model.dart`）的登录完成判定条件，修复客户端报 "Failed, bad response from server"；`account` 作为弃用的历史兼容值保留在契约枚举中；登录 / 两步验证通过后 / passkey 登录三处成功收口同步更新，契约与测试断言已同步。

## v0.1.0（2026-10-11）

首个发布版本。RustDesk 管理平台后端（Go 1.27），以 databk/rustdesk-console 的端点接口与数据库契约为兼容基准重构，不迁移任何实现代码。

### 新增

- **M0 基建**：健康检查端点、跨平台静态编译 CI（nightly / pre-release / release）、Docker 开发栈。
- **M1 后端骨架 + 认证域**：GORM 自动迁移、JWT 有状态会话（可撤销）、账户 / 2FA / passkey / OIDC 认证域、用户资料与头像管理；23 个端点契约用例通过。
- **M2 设备域 + RBAC**：设备接入协议（heartbeat / sysinfo）、设备域与设备组、下发策略、RBAC（36 个权限码 / 角色 / 用户角色指派）与用户组域；68 个端点契约用例通过，路由表 ↔ openapi.yaml ↔ 授权策略档位三方一致性测试锁定。
- **M3 全量域收口**：用户域、通讯录（含 RustDesk 客户端 legacy 兼容怪癖）、审计与仪表盘、服务器管理（经 agent 转发）、nexus 绑定与构建产物、设置域（general / smtp / ldap / frontend）、OIDC 提供者管理、更新检查；openapi.yaml 共 164 个 operation，全部契约用例通过；M3 提权 / 跨租户安全矩阵测试入库。

### 安全

- JWT 有状态会话（`login_sessions` 可撤销）、per-IP per-route 限流、敏感列显式加载与回读掩码（smtp 密码 / LDAP bindCredentials）、路径穿越防护（safeJoin + 白名单正则）、全部 403 与越权尝试写入 denied 审计。

### 其他

- 契约源：`openapi.yaml`（design-first，前端 client 由同一契约生成）。
- Docker 镜像后续提供。
