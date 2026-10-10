package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// CleanupService 过期数据定时清理：user_tokens、login_sessions、oidc_auth_states
// 与（GAP2 OQ-7）login_audits 保留期清理。
type CleanupService struct {
	tokens   *repository.UserTokenRepo
	sessions *repository.LoginSessionRepo
	states   *repository.OidcRepo
	logger   *slog.Logger
	// GAP2 OQ-7：login_audits 保留期清理（auditRetentionDays；可选装配）。
	loginAudits   *repository.LoginAuditRepo
	retentionDays func(ctx context.Context, fallback int) (int, error)
}

// NewCleanupService 构建服务。
func NewCleanupService(tokens *repository.UserTokenRepo, sessions *repository.LoginSessionRepo,
	states *repository.OidcRepo, logger *slog.Logger) *CleanupService {
	return &CleanupService{tokens: tokens, sessions: sessions, states: states, logger: logger}
}

// WithLoginAuditRetention 注入 login_audits 保留期清理（daysReader 由
// settings.GeneralService.AuditRetentionDays 实现；GAP2 OQ-7）。
func (s *CleanupService) WithLoginAuditRetention(loginAudits *repository.LoginAuditRepo, daysReader RuntimeRetentionDays) *CleanupService {
	s.loginAudits = loginAudits
	s.retentionDays = daysReader.AuditRetentionDays
	return s
}

// defaultLoginAuditRetentionFallback 保留期缺省（与 settings general
// 缺省 90 天一致；仅作读取口签名兜底，库值/env 缺省由实现方承担）。
const defaultLoginAuditRetentionFallback = 90

// RuntimeRetentionDays 保留期天数读取口（窄接口，由 service/settings
// GeneralService 实现，避免 auth → settings 直接依赖）。
type RuntimeRetentionDays interface {
	// AuditRetentionDays 返回生效审计保留天数（库值优先，缺失回退缺省）。
	AuditRetentionDays(ctx context.Context, fallback int) (int, error)
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
	removed += n
	// GAP2 OQ-7：login_audits 保留期清理（auditRetentionDays）。
	// days <= 0 视为"永久保留"（fail-safe：不因脏库值清空审计史）。
	if s.loginAudits != nil && s.retentionDays != nil {
		days, err := s.retentionDays(ctx, defaultLoginAuditRetentionFallback)
		if err != nil {
			return removed, err
		}
		if days > 0 {
			n, err = s.loginAudits.DeleteOlderThan(ctx, time.Now().Add(-time.Duration(days)*24*time.Hour))
			if err != nil {
				return removed, err
			}
			removed += n
		}
	}
	return removed, nil
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
