package servermgmt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// TestForwardErrorMatrix 锁定转发错误映射矩阵（事实③ + 共享知识 16）：
// 上游各状态码 → 映射后的固定文案与状态码；网络错误→503；非 JSON→502。
func TestForwardErrorMatrix(t *testing.T) {
	cases := []struct {
		name       string
		upstream   int    // 假 agent 返回码
		body       string // 假 agent 响应体
		wantStatus int    // 映射后期望状态码
		wantMsg    string // 映射后固定文案
	}{
		{"agent400", http.StatusBadRequest, `{}`, http.StatusBadRequest, msgInvalidRequest},
		{"agent404", http.StatusNotFound, `{}`, http.StatusNotFound, msgResourceNotFound},
		{"agent409", http.StatusConflict, `{}`, http.StatusBadRequest, msgConfigConflict},
		{"agent504", http.StatusGatewayTimeout, `{}`, http.StatusGatewayTimeout, msgOperationTimeout},
		{"agent500", http.StatusInternalServerError, `{}`, http.StatusBadGateway, msgOperationFailed},
		{"agent503", http.StatusServiceUnavailable, `{}`, http.StatusBadGateway, msgOperationFailed},
		{"agent502", http.StatusBadGateway, `{}`, http.StatusBadGateway, msgOperationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.upstream)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := NewClient([]Node{{ID: "n1", Name: "n1", URL: srv.URL, Token: "x"}}, nil)
			c.httpClient = srv.Client()
			_, _, err := c.Forward(context.Background(), http.MethodGet, "n1", "/v1/peers", nil)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			var se *rbac.StatusError
			if !errors.As(err, &se) {
				t.Fatalf("error type = %T, want *rbac.StatusError", err)
			}
			if se.Status != tc.wantStatus {
				t.Errorf("mapped status = %d, want %d", se.Status, tc.wantStatus)
			}
			if se.Message != tc.wantMsg {
				t.Errorf("mapped message = %q, want %q", se.Message, tc.wantMsg)
			}
		})
	}
}

// TestForwardSuccess 成功态透传：上游 200 JSON object 原样回传；204 无体。
func TestForwardSuccess(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"api_version":1,"node_id":"n1","services":[{"name":"hbbs"}]}`))
	}))
	defer okSrv.Close()
	c := NewClient([]Node{{ID: "n1", Name: "n1", URL: okSrv.URL, Token: "x"}}, nil)
	c.httpClient = okSrv.Client()

	st, body, err := c.Forward(context.Background(), http.MethodGet, "n1", "/v1/peers", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st != http.StatusOK {
		t.Fatalf("status = %d, want 200", st)
	}
	if string(body) != `{"api_version":1,"node_id":"n1","services":[{"name":"hbbs"}]}` {
		t.Fatalf("body = %s, want passthrough", body)
	}

	noContentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer noContentSrv.Close()
	c2 := NewClient([]Node{{ID: "n1", Name: "n1", URL: noContentSrv.URL, Token: "x"}}, nil)
	c2.httpClient = noContentSrv.Client()
	st, body, err = c2.Forward(context.Background(), http.MethodDelete, "n1", "/v1/sessions/x", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st != http.StatusNoContent || body != nil {
		t.Fatalf("no-content: status=%d body=%v, want 204 nil", st, body)
	}
}

// TestForwardNonJSON 上游非 JSON 响应体 → 502 Invalid node management response。
func TestForwardNonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("plain text, not json"))
	}))
	defer srv.Close()
	c := NewClient([]Node{{ID: "n1", Name: "n1", URL: srv.URL, Token: "x"}}, nil)
	c.httpClient = srv.Client()
	_, _, err := c.Forward(context.Background(), http.MethodGet, "n1", "/v1/peers", nil)
	var se *rbac.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error type = %T, want *rbac.StatusError", err)
	}
	if se.Status != http.StatusBadGateway || se.Message != msgInvalidResponse {
		t.Fatalf("status=%d msg=%q, want 502 %q", se.Status, se.Message, msgInvalidResponse)
	}
}

// TestForwardNetworkError 假 agent 不可达 → 503 Server node unavailable。
func TestForwardNetworkError(t *testing.T) {
	c := NewClient([]Node{{ID: "n1", Name: "n1", URL: "http://127.0.0.1:1", Token: "x"}}, nil)
	_, _, err := c.Forward(context.Background(), http.MethodGet, "n1", "/v1/peers", nil)
	var se *rbac.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error type = %T, want *rbac.StatusError", err)
	}
	if se.Status != http.StatusServiceUnavailable || se.Message != msgNodeUnavailable {
		t.Fatalf("status=%d msg=%q, want 503 %q", se.Status, se.Message, msgNodeUnavailable)
	}
}

// TestForwardNodeNotFound 未注册节点 id → 404 Server node not found。
func TestForwardNodeNotFound(t *testing.T) {
	c := NewClient(nil, nil)
	_, _, err := c.Forward(context.Background(), http.MethodGet, "ghost", "/v1/peers", nil)
	if !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("error = %v, want ErrNodeNotFound", err)
	}
}

// TestParseNodesFailFast 非法 RUSTDESK_NODES 必须返回错误（启动 fail-fast）。
func TestParseNodesFailFast(t *testing.T) {
	bad := ` [{"id":"bad id","name":"n","token":"` + string(make([]byte, 0)) + `"}]`
	if _, err := ParseNodes(bad); err == nil {
		t.Fatal("expected parse error for invalid id")
	}
	// token 过短。
	shortTok := `[{"id":"ok","name":"n","url":"https://h.test","token":"tooshort"}]`
	if _, err := ParseNodes(shortTok); err == nil {
		t.Fatal("expected parse error for short token")
	}
	// 合法。
	good := `[{"id":"ok","name":"n","url":"https://h.test/","token":"0123456789abcdef0123456789abcdef"}]`
	if _, err := ParseNodes(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// TestListStatusUnreachable 不可达节点返回 reachable:false 而非整体失败。
func TestListStatusUnreachable(t *testing.T) {
	c := NewClient([]Node{{ID: "u", Name: "u", URL: "http://127.0.0.1:1", Token: "x"}}, nil)
	st := c.ListStatus(context.Background())
	if len(st) != 1 || st[0].Reachable {
		t.Fatalf("unreachable node should be marked not reachable: %+v", st)
	}
}
