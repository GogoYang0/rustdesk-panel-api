package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/logger"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
)

// TestHealthzSmoke 与 M0 冒烟等价：GET /api/healthz 返回 status/version/time。
func TestHealthzSmoke(t *testing.T) {
	Version = "test-version"
	rt := NewRouter(RouterDeps{
		Logger:           logger.New("error"),
		Validator:        stubValidator{},
		RateLimitEnabled: true,
	})
	ts := httptest.NewServer(rt.Handler())
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/api/healthz")
	if err != nil {
		t.Fatalf("GET /api/healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["version"] != "test-version" {
		t.Errorf("version = %v", body["version"])
	}
	if _, ok := body["time"].(string); !ok {
		t.Errorf("time = %v, want rfc3339 string", body["time"])
	}
	if _, err := time.Parse(time.RFC3339, body["time"].(string)); err != nil {
		t.Errorf("time not rfc3339: %v", err)
	}
}

// TestProtectedRouteWiring 验证 Handle 注册受保护路由时 JWT 中间件生效。
func TestProtectedRouteWiring(t *testing.T) {
	rt := NewRouter(RouterDeps{
		Logger:           logger.New("error"),
		Validator:        stubValidator{},
		RateLimitEnabled: true,
	})
	rt.Handle("GET", "/api/sessions", false, 0, okHandler())
	rt.Handle("POST", "/api/login", true, 5, okHandler())
	rt.Handle("POST", "/api/users/me/password", false, 5, okHandler())
	ts := httptest.NewServer(rt.Handler())
	defer ts.Close()

	// 受保护路由未带 token → 401。
	resp, err := ts.Client().Get(ts.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("protected route without token = %d, want 401", resp.StatusCode)
	}

	// 公开路由直接放行。
	resp2, err := ts.Client().Post(ts.URL+"/api/login", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/login: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Errorf("public route = %d, want 200", resp2.StatusCode)
	}
}

// TestRateLimitWiring 验证 per-route 限流参数生效（第 2 次 429）。
func TestRateLimitWiring(t *testing.T) {
	rt := NewRouter(RouterDeps{
		Logger:           logger.New("error"),
		Validator:        stubValidator{},
		RateLimitEnabled: true,
	})
	rt.Handle("POST", "/api/login", true, 1, okHandler())
	ts := httptest.NewServer(rt.Handler())
	defer ts.Close()

	for i := 0; i < 1; i++ {
		resp, err := ts.Client().Post(ts.URL+"/api/login", "application/json", nil)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		_ = resp.Body.Close()
	}
	resp, err := ts.Client().Post(ts.URL+"/api/login", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 429 {
		t.Errorf("throttled request = %d, want 429", resp.StatusCode)
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
}

// stubValidator 始终拒绝（T01 阶段路由校验桩）。
type stubValidator struct{}

func (stubValidator) Validate(context.Context, string) (*middleware.Identity, error) {
	return nil, middleware.ErrTokenInvalid
}
