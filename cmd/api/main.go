// rustdesk-panel-api 入口。
//
// M1 起承担装配职责：加载配置 → 建立数据库连接 → 装配路由与中间件链 →
// 阻塞服务并优雅关闭。子命令：serve（默认）/ migrate / show-migrations
// （后两者于 T03 迁移基线落地时接入）。
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/database"
	loggerpkg "github.com/rustdesk-panel/rustdesk-panel-api/internal/logger"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config failed", "err", err)
		os.Exit(1)
	}
	logger := loggerpkg.New(cfg.LogLevel)
	slog.SetDefault(logger)

	// T01 阶段路由仅含公开端点（healthz），占位校验器保证装配完整；
	// T04 由 TokenService 适配器替换。
	validator := stubTokenValidator{}

	db, err := database.Open(cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		logger.Error("open database failed", "err", err)
		os.Exit(1)
	}
	if err := database.Ping(context.Background(), db); err != nil {
		logger.Error("ping database failed", "err", err)
		os.Exit(1)
	}

	if cfg.JWTSecretIsDefault() {
		// 对齐参考实现：缺省开发密钥启动打 WARNING。
		logger.Warn("JWT_SECRET is using development default; set JWT_SECRET in production")
	}

	router := server.NewRouter(server.RouterDeps{
		Logger:           logger,
		Validator:        validator,
		RateLimitEnabled: cfg.RateLimitEnabled,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := server.NewHTTPServer(cfg, router.Handler(), logger)
	if err := srv.Run(ctx); err != nil {
		logger.Error("server exited", "err", err)
		os.Exit(1)
	}
}

// stubTokenValidator 是 T01 占位校验器：始终拒绝。
// T04 由 service/auth.TokenService 的适配器替换。
type stubTokenValidator struct{}

// Validate 实现 middleware.TokenValidator。
func (stubTokenValidator) Validate(context.Context, string) (*middleware.Identity, error) {
	return nil, middleware.ErrTokenInvalid
}
