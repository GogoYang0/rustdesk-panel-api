package middleware

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
)

// maxBuckets 是 per-IP per-route 令牌桶的软上限；
// 超过后整体重置（防御性措施，正常流量远达不到）。
const maxBuckets = 65536

// RateLimiter 基于 x/time/rate 的 per-IP + per-route 令牌桶。
// routeKey 使用路由模板（如 "POST /api/login"），而非实际路径，
// 保证 /api/passkey/{guid} 这类参数化路由共享同一配额。
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rate.Limiter
	enabled bool
}

// NewRateLimiter 构建限流器；enabled=false 时 Wrap 直通。
func NewRateLimiter(enabled bool) *RateLimiter {
	return &RateLimiter{buckets: make(map[string]*rate.Limiter), enabled: enabled}
}

// Wrap 对单条路由应用 perMinute 限流；perMinute<=0 或未启用时直通。
// 桶参数：速率 = perMinute/60 每秒，突发上限 = perMinute（允许窗口内打满）。
func (rl *RateLimiter) Wrap(routeKey string, perMinute int, next http.Handler) http.Handler {
	if !rl.enabled || perMinute <= 0 {
		return next
	}
	lim := rate.Every(time.Minute / time.Duration(perMinute))
	burst := perMinute
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(routeKey+"|"+ClientIP(r), lim, burst) {
			httpx.ErrTooMany(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow 取出（或创建）对应令牌桶并尝试消费一个令牌。
func (rl *RateLimiter) allow(key string, lim rate.Limit, burst int) bool {
	rl.mu.Lock()
	if len(rl.buckets) >= maxBuckets {
		rl.buckets = make(map[string]*rate.Limiter)
	}
	l, ok := rl.buckets[key]
	if !ok {
		l = rate.NewLimiter(lim, burst)
		rl.buckets[key] = l
	}
	rl.mu.Unlock()
	return l.Allow()
}
