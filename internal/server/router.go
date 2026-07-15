package server

import (
	"log/slog"
	"net/http"
	"time"

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
}

// RouterDeps 路由装配依赖。
type RouterDeps struct {
	Logger *slog.Logger
	// Validator 为受保护路由的 token 校验器；注册受保护路由前必须注入。
	Validator middleware.TokenValidator
	// RateLimitEnabled 对应 RATE_LIMIT_ENABLED。
	RateLimitEnabled bool
}

// NewRouter 构建路由器并注册系统端点；域 handler 由 registerDomainHandlers 注入。
func NewRouter(deps RouterDeps) *Router {
	rt := &Router{
		mux:       http.NewServeMux(),
		limiter:   middleware.NewRateLimiter(deps.RateLimitEnabled),
		validator: deps.Validator,
	}
	rt.registerSystem()
	rt.registerDomainHandlers(deps)
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

// registerDomainHandlers 注册业务域路由；M1 T04/T05 逐域接入，
// T01 阶段无业务路由（仅 healthz）。
func (rt *Router) registerDomainHandlers(deps RouterDeps) {
	_ = deps
}
