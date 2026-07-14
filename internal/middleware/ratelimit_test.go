package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// TestRateLimit429 用 testing/synctest 时间驱动覆盖限流窗口：
// perMinute=2 的路由连发 3 次 → 第 3 次 429；窗口推进后恢复。
func TestRateLimit429(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rl := NewRateLimiter(true)
		var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		handler = rl.Wrap("POST /api/login", 2, handler)

		do := func(ip string) int {
			req := httptest.NewRequest("POST", "/api/login", nil)
			req.RemoteAddr = ip + ":1234"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec.Code
		}

		if got := do("1.2.3.4"); got != http.StatusOK {
			t.Fatalf("request 1 = %d, want 200", got)
		}
		if got := do("1.2.3.4"); got != http.StatusOK {
			t.Fatalf("request 2 = %d, want 200", got)
		}
		if got := do("1.2.3.4"); got != http.StatusTooManyRequests {
			t.Fatalf("request 3 = %d, want 429 (ThrottlerException)", got)
		}
		// 第 4 次确认 429 包络文案。
		req := httptest.NewRequest("POST", "/api/login", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if body := rec.Body.String(); !strings.Contains(body, `"message":"ThrottlerException: Too many requests"`) {
			t.Errorf("429 body = %s", body)
		}

		// 推进虚拟时间 31s：桶应恢复 1 个令牌（速率 2/min）。
		time.Sleep(31 * time.Second)
		synctest.Wait()
		if got := do("1.2.3.4"); got != http.StatusOK {
			t.Fatalf("request after window = %d, want 200", got)
		}

		// per-IP 隔离：另一 IP 不受影响。
		if got := do("5.6.7.8"); got != http.StatusOK {
			t.Fatalf("other ip = %d, want 200", got)
		}
	})
}

func TestRateLimitDisabled(t *testing.T) {
	rl := NewRateLimiter(false)
	handler := rl.Wrap("POST /api/login", 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/api/login", nil)
		req.RemoteAddr = "1.1.1.1:1"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("disabled limiter should pass through, got %d", rec.Code)
		}
	}
}

func TestRateLimitPerRouteIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rl := NewRateLimiter(true)
		ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
		login := rl.Wrap("POST /api/login", 1, ok)
		options := rl.Wrap("GET /api/login-options", 20, ok)

		req := httptest.NewRequest("POST", "/api/login", nil)
		req.RemoteAddr = "9.9.9.9:1"
		rec := httptest.NewRecorder()
		login.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("first login = %d", rec.Code)
		}
		// login 已耗尽，但 login-options 是不同 route，仍应放行。
		req2 := httptest.NewRequest("GET", "/api/login-options", nil)
		req2.RemoteAddr = "9.9.9.9:1"
		rec2 := httptest.NewRecorder()
		options.ServeHTTP(rec2, req2)
		if rec2.Code != 200 {
			t.Fatalf("other route should be isolated, got %d", rec2.Code)
		}
	})
}
