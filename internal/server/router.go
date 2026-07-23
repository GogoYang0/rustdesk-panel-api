package server

import (
	"log/slog"
	"net/http"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
)

// Router 装配路由表与横切链。
//
// 全局链：RequestID → Recover → AccessLog → CORS（共享知识 9 前四层）；
// 单条路由内层按注册声明附加 RateLimit → JWTAuth → Handler，
// 即整链顺序与设计一致。public=true 的路由不包 JWTAuth
// （等效于公开白名单跳过），白名单数据源即注册声明本身。
type Router struct {
	mux       *http.ServeMux
	limiter   *middleware.RateLimiter
	validator middleware.TokenValidator
	handler   http.Handler
	domain    *Domain
}

// RouterDeps 路由装配依赖。
type RouterDeps struct {
	Logger *slog.Logger
	// Validator 覆盖注入的 token 校验器（测试桩）；nil 且 DB 非空时
	// 使用 Domain 内构建的真实 TokenService。
	Validator middleware.TokenValidator
	// RateLimitEnabled 对应 RATE_LIMIT_ENABLED。
	RateLimitEnabled bool
	// DB 非空时装配认证域（T04）；nil 仅注册系统端点（契约冒烟）。
	DB *gorm.DB
	// Config 认证域服务配置（JWT/WebAuthn）。
	Config config.Config
}

// NewRouter 构建路由器：系统端点 + （注入 DB 时）认证域路由。
func NewRouter(deps RouterDeps) *Router {
	rt := &Router{
		mux:       http.NewServeMux(),
		limiter:   middleware.NewRateLimiter(deps.RateLimitEnabled),
		validator: deps.Validator,
	}
	rt.registerSystem()
	if deps.DB != nil {
		domain, err := assembleDomain(deps)
		if err != nil {
			// 装配失败属启动期错误（如 WebAuthn 配置缺失），直接 panic。
			panic("server: assemble auth domain failed: " + err.Error())
		}
		rt.domain = domain
		if rt.validator == nil {
			rt.validator = domain.Tokens
		}
		rt.registerDomainRoutes(domain)
	}
	rt.handler = middleware.Chain(rt.mux,
		middleware.RequestID,
		middleware.Recover(deps.Logger),
		middleware.AccessLog(deps.Logger),
		middleware.CORS,
	)
	return rt
}

// Handler 返回装配完成的根 handler。
func (rt *Router) Handler() http.Handler { return rt.handler }

// Domain 返回装配好的认证域容器（main 启动 cron 清理用；未装配时 nil）。
func (rt *Router) Domain() *Domain { return rt.domain }

// Handle 注册一条路由。
//
//	method   HTTP 方法（net/http 方法路由）
//	pattern  路径模板（{param} 段），与 openapi paths 一一对应
//	public   true 时跳过 JWTAuth（公开白名单）
//	perMinute>0 时启用 per-IP per-route 限流（次/分钟）
func (rt *Router) Handle(method, pattern string, public bool, perMinute int, h http.Handler) {
	if !public {
		h = middleware.JWTAuth(rt.validator)(h)
	}
	if perMinute > 0 {
		// 限流在 JWTAuth 之前（共享知识 9：... CORS → RateLimit → JWTAuth）。
		h = rt.limiter.Wrap(pattern, perMinute, h)
	}
	rt.mux.Handle(method+" "+pattern, h)
}

// hf 将方法转 handler（注册侧简化书写）。
func hf(h func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(h)
}

// registerSystem 注册系统端点（M0 契约保持不变）。
func (rt *Router) registerSystem() {
	rt.mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"version": Version,
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})
}

// registerDomainRoutes 注册认证域路由（§2.1 #1~#19）。
// 公开白名单：login、login-options、passkey/auth/*、oidc/*（共享知识 9）；
// 限流参数表：login 5、login-options 20、passkey/auth 10、oidc/auth 5、
// auth-query 120（avatars 于 T05 接入，60）。
func (rt *Router) registerDomainRoutes(d *Domain) {
	// ---- 公开端点 ----
	rt.Handle(http.MethodPost, "/api/login", true, 5, hf(d.Auth.Login))
	rt.Handle(http.MethodGet, "/api/login-options", true, 20, hf(d.Oidc.LoginOptions))
	rt.Handle(http.MethodPost, "/api/passkey/auth/begin", true, 10, hf(d.Auth.PasskeyAuthBegin))
	rt.Handle(http.MethodPost, "/api/passkey/auth/verify", true, 10, hf(d.Auth.PasskeyAuthVerify))
	rt.Handle(http.MethodPost, "/api/oidc/auth", true, 5, hf(d.Oidc.RequestAuth))
	rt.Handle(http.MethodGet, "/api/oidc/auth-query", true, 120, hf(d.Oidc.QueryAuth))
	rt.Handle(http.MethodGet, "/api/oidc/callback", true, 0, hf(d.Oidc.Callback))

	// ---- 受保护端点（JWT）----
	rt.Handle(http.MethodPost, "/api/logout", false, 0, hf(d.Auth.Logout))
	rt.Handle(http.MethodPost, "/api/currentUser", false, 0, hf(d.Auth.CurrentUser))
	rt.Handle(http.MethodPost, "/api/2fa/setup", false, 0, hf(d.Auth.SetupTfa))
	rt.Handle(http.MethodPost, "/api/2fa/verify", false, 0, hf(d.Auth.VerifyTfa))
	rt.Handle(http.MethodDelete, "/api/2fa", false, 0, hf(d.Auth.DisableTfa))
	rt.Handle(http.MethodPost, "/api/passkey/register/begin", false, 0, hf(d.Auth.PasskeyRegisterBegin))
	rt.Handle(http.MethodPost, "/api/passkey/register/verify", false, 0, hf(d.Auth.PasskeyRegisterVerify))
	rt.Handle(http.MethodGet, "/api/passkey/list", false, 0, hf(d.Auth.PasskeyList))
	rt.Handle(http.MethodDelete, "/api/passkey/{guid}", false, 0, hf(d.Auth.PasskeyDelete))
	rt.Handle(http.MethodPost, "/api/passkey/tfa", false, 0, hf(d.Auth.PasskeyTfaToggle))
	rt.Handle(http.MethodGet, "/api/sessions", false, 0, hf(d.Auth.SessionsList))
	rt.Handle(http.MethodDelete, "/api/sessions/{jti}", false, 0, hf(d.Auth.SessionRevoke))

	// ---- 用户自身端点（JWT；#24 头像静态公开限流 60）----
	rt.Handle(http.MethodPatch, "/api/users/me", false, 0, hf(d.User.UpdateMe))
	rt.Handle(http.MethodPatch, "/api/users/me/password", false, 5, hf(d.User.ChangePassword))
	rt.Handle(http.MethodPost, "/api/users/me/avatar", false, 10, hf(d.User.UploadAvatar))
	rt.Handle(http.MethodDelete, "/api/users/me/avatar", false, 10, hf(d.User.DeleteAvatar))
	rt.Handle(http.MethodGet, "/api/avatars/{filename}", true, 60, hf(d.User.GetAvatar))
}
