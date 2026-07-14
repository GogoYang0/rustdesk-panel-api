// Package middleware 提供 HTTP 请求链横切件。
//
// 链序（共享知识 9）：RequestID → Recover → AccessLog(slog JSON) →
// CORS(credentials:true) → RateLimit(per-route) → JWTAuth → Handler。
// 全局四件套由 internal/server/router.go 统一编排；
// RateLimit 与 JWTAuth 在单条路由内按注册声明附加（RateLimit 在前）。
package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
	"uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/logger"
)

// Chain 按 first→last（外→内）顺序组合中间件。
func Chain(final http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		final = mws[i](final)
	}
	return final
}

// RequestID 提取或生成 X-Request-Id（标准库 uuid v4），注入 context 与响应头。
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-Id"))
		if id == "" {
			id = uuid.New().String()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(logger.ContextWithRequestID(r.Context(), id)))
	})
}

// statusRecorder 捕获响应状态码供访问日志使用。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// Recover panic 兜底 → 500 固定包络（不泄漏堆栈给客户端）。
func Recover(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					base.Error("panic recovered",
						"requestId", logger.RequestIDFromContext(r.Context()),
						"method", r.Method, "path", r.URL.Path,
						"panic", rec, "stack", string(debug.Stack()))
					httpx.ErrInternal(w)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// AccessLog 输出 slog JSON 访问日志（method/path/status/耗时/IP/requestId）。
func AccessLog(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			base.Info("http access",
				"requestId", logger.RequestIDFromContext(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"durationMs", time.Since(start).Milliseconds(),
				"ip", ClientIP(r),
			)
		})
	}
}

// CORS 允许凭据并回显 Origin（对齐参考 enableCors({credentials: true})）；
// OPTIONS 预检短路返回 204。
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP 提取客户端 IP：X-Forwarded-For 首段 → X-Real-Ip → RemoteAddr。
func ClientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if i := strings.IndexByte(xf, ','); i >= 0 {
			xf = xf[:i]
		}
		if ip := strings.TrimSpace(xf); ip != "" {
			return ip
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-Ip")); xr != "" {
		return xr
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
