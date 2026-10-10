package middleware

import (
	"bytes"
	"encoding/json"
	"io"
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

// deviceMaxBody 设备端协议报文读取上限（1 MiB，远超实际心跳/系统信息体量）。
const deviceMaxBody = 1 << 20

// DeviceRateLimiter 设备维度限流器（M2 设备端协议专用，设计 §1.4）：
// tracker 取 body.id → body.uuid → IP 回退，键为 {tracker}:{method}:{route}。
// 与 per-IP RateLimiter 并行使用（heartbeat 10/min、sysinfo 5/min）。
type DeviceRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rate.Limiter
	enabled bool
}

// NewDeviceRateLimiter 构建设备维度限流器；enabled=false 时 Wrap 直通。
func NewDeviceRateLimiter(enabled bool) *DeviceRateLimiter {
	return &DeviceRateLimiter{buckets: make(map[string]*rate.Limiter), enabled: enabled}
}

// deviceTrackerBody 宽松解析心跳/系统信息报文中可作 tracker 的字段
// （仅提取 id/uuid；解析失败回退 IP，不参与严格校验）。
type deviceTrackerBody struct {
	ID   string `json:"id"`
	UUID string `json:"uuid"`
}

// Wrap 对设备端协议路由应用 perMinute 限流：
// 读取请求体（上限 deviceMaxBody）→ 提取 tracker → 回灌 body →
// 令牌桶判定，超限 429（与全局 Throttler 同文案）。
func (dl *DeviceRateLimiter) Wrap(routeKey string, perMinute int, next http.Handler) http.Handler {
	if !dl.enabled || perMinute <= 0 {
		return next
	}
	lim := rate.Every(time.Minute / time.Duration(perMinute))
	burst := perMinute
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, deviceMaxBody))
		if err == nil {
			// 回灌请求体供后续 DecodeJSON 读取。
			r.Body = io.NopCloser(bytes.NewReader(body))
			var probe deviceTrackerBody
			_ = json.Unmarshal(body, &probe)
			tracker := probe.ID
			if tracker == "" {
				tracker = probe.UUID
			}
			if tracker == "" {
				tracker = ClientIP(r)
			}
			if !dl.allow(tracker+"|"+r.Method+" "+routeKey, lim, burst) {
				httpx.ErrTooMany(w)
				return
			}
		}
		// 读体失败（连接中断等）时直接透传，由绑定层报错。
		next.ServeHTTP(w, r)
	})
}

// allow 与 RateLimiter.allow 同构（独立桶空间）。
func (dl *DeviceRateLimiter) allow(key string, lim rate.Limit, burst int) bool {
	dl.mu.Lock()
	if len(dl.buckets) >= maxBuckets {
		dl.buckets = make(map[string]*rate.Limiter)
	}
	l, ok := dl.buckets[key]
	if !ok {
		l = rate.NewLimiter(lim, burst)
		dl.buckets[key] = l
	}
	dl.mu.Unlock()
	return l.Allow()
}
