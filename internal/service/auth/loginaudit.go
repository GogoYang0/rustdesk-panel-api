// Package auth 本文件：GAP2 登录审计（G3）——login_audits best-effort
// 记录器与请求元数据（IP/User-Agent）上下文透传。
//
// 写入失败仅告警不阻断登录主流程（G3；模式同 rbac/audit.go RecordDenied）。
// IP/UA 由 handler 侧以 WithLoginMeta 注入 ctx（服务层不改签名），
// deviceId/deviceUuid 来自登录请求载荷（id/uuid）。
package auth

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// loginMetaKey ctx 键（登录审计元数据）。
type loginMetaKeyType struct{}

var loginMetaKey loginMetaKeyType

// LoginMeta 登录审计请求元数据。
type LoginMeta struct {
	IP        string
	UserAgent string
}

// WithLoginMeta 从 HTTP 请求提取 IP/User-Agent 并注入 ctx
// （handler 侧在调用登录域服务前包装）。
func WithLoginMeta(ctx context.Context, r *http.Request) context.Context {
	meta := LoginMeta{UserAgent: r.Header.Get("User-Agent")}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		meta.IP = host
	} else {
		meta.IP = r.RemoteAddr
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		// 取首个代理跳（客户端原文锚点）。
		for i := 0; i < len(fwd); i++ {
			if fwd[i] == ',' {
				meta.IP = trimSpace(fwd[:i])
				break
			}
		}
		if meta.IP == "" {
			meta.IP = fwd
		}
	}
	return context.WithValue(ctx, loginMetaKey, meta)
}

// metaFromCtx 读取登录元数据（未注入时零值：空串列合法形态）。
func metaFromCtx(ctx context.Context) LoginMeta {
	if v, ok := ctx.Value(loginMetaKey).(LoginMeta); ok {
		return v
	}
	return LoginMeta{}
}

// trimSpace 去首尾空白（避免仅为此引入 strings）。
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// LoginAuditEntry 登录审计行载荷（GAP2 设计 §3.4）。
type LoginAuditEntry struct {
	UserGuid   *string // 可空：用户不存在/纯枚举尝试
	Username   string  // 登录尝试输入原文（审计锚点）
	Result     string  // entity.LoginAuditResult* 六枚举
	Method     string  // entity.LoginAuditMethod* 五枚举
	DeviceId   string
	DeviceUuid string
	Reason     string // 固定文案（bad_credentials / user_disabled / tfa_code_invalid 等）
}

// LoginAuditRecorder login_audits best-effort 记录器（G3）。
type LoginAuditRecorder struct {
	repo   *repository.LoginAuditRepo
	logger *slog.Logger
}

// NewLoginAuditRecorder 构建记录器（repo 可为 nil，nil 时静默跳过——
// 单测环境未装配 login_audits 表）。
func NewLoginAuditRecorder(repo *repository.LoginAuditRepo, logger *slog.Logger) *LoginAuditRecorder {
	return &LoginAuditRecorder{repo: repo, logger: logger}
}

// Record 写入一条登录审计：任何失败仅告警，不向上传播（G3）。
func (r *LoginAuditRecorder) Record(ctx context.Context, e LoginAuditEntry) {
	if r == nil || r.repo == nil {
		return
	}
	meta := metaFromCtx(ctx)
	rec := &entity.LoginAudit{
		UserGuid:   e.UserGuid,
		Username:   e.Username,
		Result:     e.Result,
		Method:     e.Method,
		IP:         meta.IP,
		UserAgent:  meta.UserAgent,
		DeviceId:   e.DeviceId,
		DeviceUuid: e.DeviceUuid,
		Reason:     e.Reason,
	}
	if err := r.repo.Create(ctx, rec); err != nil && r.logger != nil {
		r.logger.Warn("login audit write failed (best-effort)", "result", e.Result, "method", e.Method, "err", err)
	}
}
