# rustdesk-panel-api

RustDesk 管理平台后端（Go 1.27）。以 [databk/rustdesk-console](https://github.com/databk/rustdesk-console) 的**端点接口与数据库契约**为兼容基准重构，不迁移任何实现代码。

## 当前状态

- **M0 基建**（已完成）：健康检查端点、跨平台静态编译 CI（nightly / pre-release / release）、Docker 开发栈。
- **M1 后端骨架 + 认证域**（已完成）：GORM 自动迁移、JWT 有状态会话、账户/2FA/passkey/OIDC 认证域、用户资料与头像管理；**全部 23 个端点契约用例通过（openapi.yaml 双向校验）**。
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
