# 更新日志（Changelog）

本项目的所有重要变更将记录在本文件中。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 简化版。

## [0.3.0] - 2026-10-11

定级说明：本批次最高级别为 [feature]（新增端点 + 契约兼容扩展），按定级规则升 minor：v0.2.0 → v0.3.0。

### 新增

- **[feature] 策略配置项预设目录**：新增 `GET /api/strategies/presets`（Perm `strategies.view`）——编译期常量表 **72 项**，键全集取自官方客户端 `libs/base/src/config/keys.rs` 策略相关子集，按 security / connection / display / permission / other 五分类，含 key / type / default_value / description（契约新增 `StrategyOptionPreset`）。
- **[feature] 强制 MFA 开启前置校验与组内解绑守卫**：`PUT /api/settings/mfa` 开启 `enforceGlobal` 或新增强制组前，校验目标用户中存在未绑定 TOTP 且未开启 passkey-2FA 者 → 400 拒绝（契约新增 `MfaEnforcementConflict`，返回未绑定名单 guid / username / display_name / user_group_name）；`DELETE /api/2fa` 与 `DELETE /api/passkey/{guid}` 命中强制策略 → 403 拒绝解绑，需先移出强制范围。
- **[feature] 更新检查对接 GitHub Releases**：frontend / backend 版本源分别改为 `GogoYang0/rustdesk-panel-web`、`GogoYang0/rustdesk-panel-api` 的 `/releases/latest`（tag_name 去 `v` 即 latest，release body 即 changelog，html_url 即 downloadUrl）；10s 超时，GitHub 不可达回退 current==latest 无更新；遥测上报保留 best-effort（`GITHUB_API_BASE` env 供测试覆写）。

### 变更

- 契约兼容扩展：审计上报 `conn_id` string→**integer**、标签 `color` int32→**int64**、`GET /api/devices` 新增 `guid` 精确过滤查询参数、更新检查响应新增 `changelog` / `downloadUrl` 字段；openapi.yaml 173 operation。
- 更新检查版本错位场景（MIN-01）：`latest` / `changelog` / `downloadUrl` 在 GitHub 可达时始终来自 GitHub 响应，`hasUpdate` 仅作比较结果；`applyFrontendVersion` 无更新时同步清空 release 信息（含单测覆盖 backend≥latest 且 frontend<latest 错位场景）。

### 修复（官方客户端协议兼容，对照 rustdesk master 逐字取证）

- 审计上报 `conn_id` 数值上报：官方 `post_conn_audit` 的 `self.inner.id` 为 i32 数值，此前 string 契约直接 400，为审计四页无数据根因；服务端落库仍转字符串。
- 审计上报 `action='close'` 正确落 `closedAt`（此前被幂等分支吞掉，活跃连接永不关闭）。
- 通讯录（ab）端点容忍官方客户端 Content-Length:0 空 body POST + query 传参：ab / id / alias / tags / tagMode 自 query 回填；`ab/tags` 空 body 语义为拉取标签列表（等价 GET），非空体才全量替换 → 修复拉取通讯录 400。
- 标签 `color` 越界：int32→int64（官方 Dart `Color.value` 为 0xAARRGGBB 无符号 32 位，可超 int32 上限）→ 修复添加标签 400。
- 断开连接 `connIds` 契约放宽（去 required / minItems）：空数组/缺省 = 断开该设备全部活跃连接（从连接审计未关闭行收集数值 connId 入队，心跳以 disconnect 键下发）→ 修复 web 整机断开 400。
- 设备详情 `guid` 精确查询：`listDevices` 新增 guid 过滤（设备名 / 用户名 LIKE sysinfos 列）→ 配合 web 设备详情页定位修复。

### 兼容性

- 本批次契约均为兼容性扩展（新增字段 / 放宽校验 / 新增可选查询参数），无破坏性变更；**部署请 api / web 同步升级**（web v0.3.0 已适配 changelog 展示、guid 查询与 connIds 空数组语义）。
- v0 阶段稳定性提醒：接口仍可能随官方客户端取证结果微调，生产部署请锁定版本并关注后续 changelog。

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
