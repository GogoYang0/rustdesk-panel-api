// Package config 汇集运行时配置。
//
// M1 起基于 caarlos0/env v11 声明式加载：
// JWT/WebAuthn/管理员种子/限流开关等全部通过环境变量注入；
// JWT 过期天数与 WebAuthn RP 配置在 M3 接入 system_settings 之前
// 以 env 承载（批复事项 #7），届时 env 变为 fallback。
package config

import (
	"errors"

	"github.com/caarlos0/env/v11"
)

// devFallbackSecret 是与参考实现对齐的开发缺省密钥；
// 生产部署必须通过 JWT_SECRET 覆盖（启动时命中缺省值会打 WARNING）。
const devFallbackSecret = "rustdesk-panel-dev-secret"

// Config 运行时配置（全部字段可通过环境变量覆盖）。
type Config struct {
	// HTTP 监听地址。
	HTTPAddr string `env:"HTTP_ADDR" envDefault:":8080"`

	// 数据库：mysql | sqlite；DSN 语义跟随驱动。
	// MySQL 建议 DSN 携带 parseTime=true&loc=Local（对齐 TypeORM 语义）。
	DBDriver string `env:"DB_DRIVER" envDefault:"sqlite"`
	DBDSN    string `env:"DB_DSN" envDefault:"./rustdesk-panel.db"`

	// JWT：HS256 密钥与有效期（天）。缺省 30 天。
	JWTSecret     string `env:"JWT_SECRET" envDefault:"rustdesk-panel-dev-secret"`
	JWTExpiryDays int    `env:"JWT_EXPIRY_DAYS" envDefault:"30"`

	// 数据目录（头像等静态文件根；M3 亦承载 nexus 产物 DATA_DIR/nexus）。
	DataDir string `env:"DATA_DIR" envDefault:"./data"`

	// M3 服务器域（设计事实③/共享知识 19）：中继节点清单，JSON 数组
	// [{id,name,url,token}]。空串=无节点（合法，服务器域列表为空）；
	// 格式/取值校验（id 唯一、url 纯 origin、token≥32、≤100 节点）在
	// servermgmt 包启动装配时执行，失败 fail-fast 终止进程（T06）。
	RustdeskNodes string `env:"RUSTDESK_NODES" envDefault:""`

	// M3 更新检查渠道（设计事实④/共享知识 19）：stable | nightly。
	UpdateChannel string `env:"UPDATE_CHANNEL" envDefault:"stable"`

	// M3 nexus 代理上游（设计事实⑤/共享知识 19）：固定代理
	// api.databk.top；仅测试覆写。NEXUS_UPSTREAM 为空时回落缺省。
	NexusUpstream string `env:"NEXUS_UPSTREAM" envDefault:"https://api.databk.top"`

	// v0.2.1 更新检查版本源：GitHub API 基址（仅测试覆写）。
	GitHubAPIBase string `env:"GITHUB_API_BASE" envDefault:"https://api.github.com"`

	// WebAuthn Relying Party 配置（M3 起降级为 fallback：库值
	// general.webauthn* 优先，见 M1 批复 #7）。
	WebAuthnRPID    string   `env:"WEBAUTHN_RP_ID" envDefault:"localhost"`
	WebAuthnOrigins []string `env:"WEBAUTHN_ORIGINS" envSeparator:"," envDefault:"http://localhost:8080"`

	// M3 OIDC env fallback（设计事实⑧/M1 批复 #7）：oidc_providers 表
	// 无 enabled 记录时降级启用本组配置；OIDC_ISSUER 为空即视为未配置。
	OidcIssuer       string `env:"OIDC_ISSUER" envDefault:""`
	OidcClientID     string `env:"OIDC_CLIENT_ID" envDefault:""`
	OidcClientSecret string `env:"OIDC_CLIENT_SECRET" envDefault:""`
	OidcScope        string `env:"OIDC_SCOPE" envDefault:""`

	// 面板版本号（update-check 遥测 current 值与构建信息）。
	Version string `env:"APP_VERSION" envDefault:"0.3.0"`

	// 默认管理员种子（批复事项 #5：databk 缺省 + env 覆盖）。
	AdminUsername string `env:"ADMIN_USERNAME" envDefault:"databk"`
	AdminEmail    string `env:"ADMIN_EMAIL" envDefault:"databk@github.com"`
	AdminPassword string `env:"ADMIN_PASSWORD" envDefault:"databk"`

	// 限流开关（per-IP per-route，参数表见 internal/server/router.go）。
	RateLimitEnabled bool `env:"RATE_LIMIT_ENABLED" envDefault:"true"`

	// 日志级别：debug | info | warn | error。
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
}

// JWTSecretIsDefault 报告 JWT_SECRET 是否仍为开发缺省值。
func (c Config) JWTSecretIsDefault() bool { return c.JWTSecret == devFallbackSecret }

// Load 从环境加载配置并做基础校验。
func Load() (Config, error) {
	cfg := Config{}
	if err := env.Parse(&cfg); err != nil {
		return Config{}, errors.Join(errors.New("config: parse env failed"), err)
	}
	if cfg.JWTExpiryDays <= 0 {
		return Config{}, errors.New("config: JWT_EXPIRY_DAYS must be > 0")
	}
	if cfg.DBDriver != "mysql" && cfg.DBDriver != "sqlite" {
		return Config{}, errors.New("config: DB_DRIVER must be mysql or sqlite")
	}
	if cfg.UpdateChannel != "stable" && cfg.UpdateChannel != "nightly" {
		return Config{}, errors.New("config: UPDATE_CHANNEL must be stable or nightly")
	}
	return cfg, nil
}
