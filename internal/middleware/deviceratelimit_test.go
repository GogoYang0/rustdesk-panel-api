package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
)

// buildDeviceHandler 构建带设备维度限流的 handler 与请求构造器。
func buildDeviceHandler(perMinute int, body string) (http.Handler, func(string, string) int) {
	dl := NewDeviceRateLimiter(true)
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟业务层回读 body（回灌语义验证）。
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf[:n])
	})
	handler = dl.Wrap("POST /api/heartbeat", perMinute, handler)
	do := func(tracker, payload string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", strings.NewReader(payload))
		req.RemoteAddr = tracker + ":9999"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	return handler, do
}

// TestDeviceRateLimitHeartbeat 第 11 次心跳 429（10/min）。
func TestDeviceRateLimitHeartbeat(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, do := buildDeviceHandler(10, `{"id":"123456789","uuid":"dev-1","ver":1000015,"modified_at":1}`)

		for i := 1; i <= 10; i++ {
			if got := do("ignored", `{"id":"123456789","uuid":"dev-1","ver":1,"modified_at":1}`); got != http.StatusOK {
				t.Fatalf("heartbeat %d = %d, want 200", i, got)
			}
		}
		if got := do("ignored", `{"id":"123456789","uuid":"dev-1","ver":1,"modified_at":1}`); got != http.StatusTooManyRequests {
			t.Fatalf("heartbeat 11 = %d, want 429", got)
		}
	})
}

// TestDeviceRateLimitSysinfo 第 6 次 sysinfo 429（5/min）。
func TestDeviceRateLimitSysinfo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dl := NewDeviceRateLimiter(true)
		handler := dl.Wrap("POST /api/sysinfo", 5, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		do := func(payload string) int {
			req := httptest.NewRequest(http.MethodPost, "/api/sysinfo", strings.NewReader(payload))
			req.RemoteAddr = "9.9.9.9:1"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec.Code
		}
		for i := 1; i <= 5; i++ {
			if got := do(`{"uuid":"dev-1","hostname":"h"}`); got != http.StatusOK {
				t.Fatalf("sysinfo %d = %d, want 200", i, got)
			}
		}
		if got := do(`{"uuid":"dev-1","hostname":"h"}`); got != http.StatusTooManyRequests {
			t.Fatalf("sysinfo 6 = %d, want 429", got)
		}
	})
}

// TestDeviceRateLimitTrackerIsolation 设备间互不影响；tracker 顺序
// id → uuid → IP；body 回灌后业务层可读。
func TestDeviceRateLimitTrackerIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, do := buildDeviceHandler(2, "")

		// 同一 uuid 的第 3 次请求 429。
		if got := do("1.1.1.1", `{"id":"d1","uuid":"u1"}`); got != http.StatusOK {
			t.Fatalf("req 1 = %d", got)
		}
		if got := do("1.1.1.1", `{"id":"d1","uuid":"u1"}`); got != http.StatusOK {
			t.Fatalf("req 2 = %d", got)
		}
		if got := do("1.1.1.1", `{"id":"d1","uuid":"u1"}`); got != http.StatusTooManyRequests {
			t.Fatalf("req 3 = %d, want 429", got)
		}
		// 另一设备（不同 id）不受影响。
		if got := do("1.1.1.1", `{"id":"d2","uuid":"u2"}`); got != http.StatusOK {
			t.Fatalf("other device = %d, want 200", got)
		}
		// tracker 顺序：id 优先于 uuid——同 id 不同 uuid 仍 429。
		if got := do("1.1.1.1", `{"id":"d1","uuid":"u-other"}`); got != http.StatusTooManyRequests {
			t.Fatalf("same id other uuid = %d, want 429", got)
		}
		// 无 id 有 uuid：以 uuid 为 tracker。
		if got := do("1.1.1.1", `{"uuid":"u-solo"}`); got != http.StatusOK {
			t.Fatalf("uuid tracker = %d, want 200", got)
		}
		// 无 id 无 uuid：回退 IP（同 IP 独立桶，perMinute=2 → 第 3 次 429）。
		if got := do("2.2.2.2", `{}`); got != http.StatusOK {
			t.Fatalf("ip fallback 1 = %d, want 200", got)
		}
		if got := do("2.2.2.2", `{}`); got != http.StatusOK {
			t.Fatalf("ip fallback 2 = %d, want 200", got)
		}
		if got := do("2.2.2.2", `{}`); got != http.StatusTooManyRequests {
			t.Fatalf("ip fallback 3 = %d, want 429", got)
		}
	})
}
