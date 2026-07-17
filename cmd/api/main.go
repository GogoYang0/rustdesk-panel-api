// rustdesk-panel-api 入口。
//
// 子命令：serve（默认）/ migrate / show-migrations。
// serve：加载配置 → 建库 → 装配路由与中间件链 → 阻塞服务并优雅关闭。
// migrate：执行迁移基线 + 幂等种子（对齐参考 db:migrate）。
// show-migrations：列出迁移与应用状态（对齐参考 db:show）。
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
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/migration"
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

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			if err := runMigrate(cfg, logger); err != nil {
				logger.Error("migrate failed", "err", err)
				os.Exit(1)
			}
			return
		case "show-migrations":
			if err := runShowMigrations(cfg, logger); err != nil {
				logger.Error("show-migrations failed", "err", err)
				os.Exit(1)
			}
			return
		case "serve":
		default:
			logger.Error("unknown subcommand", "cmd", os.Args[1])
			os.Exit(2)
		}
	}
	runServe(cfg, logger)
}

// runServe 默认子命令：装配并阻塞服务。
func runServe(cfg config.Config, logger *slog.Logger) {
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

// runMigrate 执行迁移基线 + 幂等种子。
func runMigrate(cfg config.Config, logger *slog.Logger) error {
	db, err := database.Open(cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return err
	}
	m, err := migration.New(db, cfg.DBDriver)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil {
		return err
	}
	if err := database.Seed(context.Background(), db, cfg.AdminUsername, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		return err
	}
	v, dirty, err := m.Version()
	if err != nil {
		return err
	}
	logger.Info("migrate done", "driver", cfg.DBDriver, "version", v, "dirty", dirty)
	return nil
}

// runShowMigrations 列出迁移与应用状态。
func runShowMigrations(cfg config.Config, logger *slog.Logger) error {
	db, err := database.Open(cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return err
	}
	m, err := migration.New(db, cfg.DBDriver)
	if err != nil {
		return err
	}
	infos, err := m.Show()
	if err != nil {
		return err
	}
	for _, info := range infos {
		status := "pending"
		if info.Applied {
			status = "applied"
		}
		logger.Info("migration", "version", info.Version, "name", info.Name, "status", status)
	}
	return nil
}

// stubTokenValidator 是 T01 占位校验器：始终拒绝。
// T04 由 service/auth.TokenService 的适配器替换。
type stubTokenValidator struct{}

// Validate 实现 middleware.TokenValidator。
func (stubTokenValidator) Validate(context.Context, string) (*middleware.Identity, error) {
	return nil, middleware.ErrTokenInvalid
}
