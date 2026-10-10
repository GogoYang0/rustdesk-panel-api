# 更新日志（Changelog）

本项目的所有重要变更将记录在本文件中。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 简化版。

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
