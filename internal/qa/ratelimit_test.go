package qa

import (
	"net/http"
	"sync"
	"testing"
)

// ---- 限流：并发 429 包络形状 / per-route 隔离（端到端） ----

// TestQARateLimitConcurrencyAndEnvelopeShape 并发视角限流验证：
// login 配额 5/min（burst=5），同一 IP 短时间并发 20 个错误密码登录，
// 必须：成功消耗（401）不超过配额、其余全部 429；
// 且每个 429 响应都是精确的 NestJS 包络形状
// {statusCode:429, message:"ThrottlerException: Too many requests", error:"Too Many Requests"}。
func TestQARateLimitConcurrencyAndEnvelopeShape(t *testing.T) {
	ts := newQAServer(t)

	const total = 20
	type result struct {
		status int
		body   map[string]any
	}
	results := make([]result, total)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // 尽量同时放行，逼近真实并发洪峰
			status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login", map[string]any{
				"username": "databk", "password": "definitely-wrong",
			}, nil)
			results[i] = result{status: status, body: parsed}
		}(i)
	}
	close(start)
	wg.Wait()

	count429, count401 := 0, 0
	for _, r := range results {
		switch r.status {
		case http.StatusTooManyRequests:
			count429++
			// 包络形状逐字段断言（比既有用例的 Contains 更严格）。
			assertEnvelope(t, r.status, r.body, http.StatusTooManyRequests, "ThrottlerException: Too many requests")
		case http.StatusUnauthorized:
			count401++
		default:
			t.Fatalf("unexpected status %d: %v", r.status, r.body)
		}
	}
	// burst=5 + 测试窗口内补充令牌 < 1：401 ≤ 6、429 ≥ 14 为稳定断言。
	if count401 > 6 {
		t.Errorf("accepted logins = %d, must not exceed burst 5 + refill 1", count401)
	}
	if count429 < 14 {
		t.Errorf("throttled = %d, want >= 14 of %d", count429, total)
	}
	if count429+count401 != total {
		t.Errorf("status accounting mismatch: %d + %d != %d", count429, count401, total)
	}
}

// TestQARateLimitPerRouteIsolationEndToEnd 端到端 per-route 隔离：
// 同一 IP 把 /api/login（5/min）打满后，/api/login-options（独立 20/min 桶）
// 必须不受影响正常 200——限流键为路由模板而非全局。
func TestQARateLimitPerRouteIsolationEndToEnd(t *testing.T) {
	ts := newQAServer(t)

	// 打满 login 配额：5 次 401 + 第 6 次 429。
	for i := 0; i < 5; i++ {
		status, _, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login", map[string]any{
			"username": "databk", "password": "wrong",
		}, nil)
		if status != 401 {
			t.Fatalf("warmup login #%d = %d, want 401: %s", i+1, status, raw)
		}
	}
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login", map[string]any{
		"username": "databk", "password": "wrong",
	}, nil)
	assertEnvelope(t, status, parsed, http.StatusTooManyRequests, "ThrottlerException: Too many requests")

	// 同 IP、不同路由 → 不受 login 桶影响。
	status, _, raw := doJSON(t, ts.TS.Client(), http.MethodGet, ts.TS.URL+"/api/login-options", nil, nil)
	if status != 200 {
		t.Fatalf("login-options after login exhaustion = %d, want 200 (per-route isolation): %s", status, raw)
	}
}
