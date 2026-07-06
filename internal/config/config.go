// Package config 汇集运行时配置。
// M0 仅承载 HTTP 监听与数据库占位项，后续按模块扩展
// （认证密钥、SMTP、OIDC、LDAP、节点 agent 注册表 RUSTDESK_NODES 等）。
package config

import "os"

type Config struct {
	HTTPAddr string
	DBDriver string // mysql | sqlite
	DBDSN    string
}

func Load() Config {
	return Config{
		HTTPAddr: envOr("HTTP_ADDR", ":8080"),
		DBDriver: envOr("DB_DRIVER", "sqlite"),
		DBDSN:    envOr("DB_DSN", "./rustdesk-panel.db"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
