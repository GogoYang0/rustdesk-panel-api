# rustdesk-panel-api

RustDesk 管理平台后端（Go 1.27）。以 [databk/rustdesk-console](https://github.com/databk/rustdesk-console) 的**端点接口与数据库契约**为兼容基准重构，不迁移任何实现代码。

## 当前状态

- **M0 基建**：健康检查端点、跨平台静态编译 CI（nightly / pre-release / release）、Docker 开发栈。
- 契约源：`openapi.yaml`（design-first，前端 client 由同一契约生成）。

## 本地开发

```sh
# SQLite 快速启动
HTTP_ADDR=:8080 go run ./cmd/api

# MySQL 开发栈
docker compose up -d --build

# 验证
curl http://localhost:8080/api/healthz
```

## 构建产物命名

```
rustdesk-panel-api_<version>_<os>_<arch>.tar.gz   # windows 为 .zip
rustdesk-panel-api_1.2.0_linux_amd64.tar.gz       # release
rustdesk-panel-api_1.2.0-rc.1_darwin_arm64.tar.gz # pre-release
rustdesk-panel-api_0.0.0-nightly.20261008_linux_amd64.tar.gz  # nightly
```

## 分支模型

classic gitflow（main/develop + feature/release/hotfix），规范定义见 `.gitflow/workflow.json`。提交遵循 Conventional Commits。
