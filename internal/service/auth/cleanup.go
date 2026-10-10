package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// CleanupService 过期数据定时清理：user_tokens、login_sessions、oidc_auth_states。
type CleanupService struct {
	tokens   *repository.UserTokenRepo
	sessions *repository.LoginSessionRepo
	states   *repository.OidcRepo
	logger   *slog.Logger
}

// NewCleanupService 构建服务。
func NewCleanupService(tokens *repository.UserTokenRepo, sessions *repository.LoginSessionRepo,
	states *repository.OidcRepo, logger *slog.Logger) *CleanupService {
	return &CleanupService{tokens: tokens, sessions: sessions, states: states, logger: logger}
}

// RunOnce 单轮清理；返回清理条数（供测试断言）。
func (s *CleanupService) RunOnce(ctx context.Context) (int64, error) {
	var removed int64
	// 过期 token：expiresAt < now（已过期即不可再通过 Validate）。
	n, err := s.tokens.DeleteExpired(ctx, time.Now())
	if err != nil {
		return removed, err
	}
	removed += n
	// 过期两步验证会话。
	n, err = s.sessions.DeleteExpired(ctx)
	if err != nil {
		return removed, err
	}
	removed += n
	// 过期 OIDC 授权中间态。
	n, err = s.states.DeleteExpiredStates(ctx, time.Now())
	if err != nil {
		return removed, err
	}
	return removed + n, nil
}

// StartCleanup 启动 robfig/cron 每小时清理（设计 T04：cron 清理）；
// 返回停止函数。ctx 取消后清理协程随之失效。
func StartCleanup(ctx context.Context, svc *CleanupService, logger *slog.Logger) func() {
	c := cron.New()
	if _, err := c.AddFunc("@hourly", func() {
		removed, err := svc.RunOnce(ctx)
		switch {
		case err != nil:
			logger.Warn("auth cleanup failed", "err", err)
		case removed > 0:
			logger.Info("auth cleanup done", "removed", removed)
		}
	}); err != nil {
		logger.Error("auth cleanup schedule failed", "err", err)
		return func() {}
	}
	c.Start()
	return func() { <-c.Stop().Done() }
}
