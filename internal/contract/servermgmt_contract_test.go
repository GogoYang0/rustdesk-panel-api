// servermgmt_contract_test.go 服务器域（M3 T06，事实③）10 端点契约用例：
// 以 openapi.yaml 为准绳，对 servers 域全部 operationId 做请求/响应双向
// 校验；并以假 agent（httptest）逐条锁定错误映射矩阵（共享知识 16）。
//
// 错误映射矩阵在 internal/service/servermgmt/forward_test.go 已对转发器
// 单体逐条断言；本文件从 HTTP 契约层再次端到端锁定，两条防线互补。
package contract

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/server"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// fakeAgent 假 agent：按 pathStatus 返回指定状态码，pathBody 覆盖响应体；
// 未命中路径回 200 + 合法 JSON object。
type fakeAgent struct {
	srv *httptest.Server
}

// newFakeAgent 构建假 agent 并返回其 origin URL（pathBody 可为 nil）。
func newFakeAgent(t *testing.T, pathStatus map[string]int, pathBody map[string]string) (string, *fakeAgent) {
	t.Helper()
	if pathStatus == nil {
		pathStatus = map[string]int{}
	}
	if pathBody == nil {
		pathBody = map[string]string{}
	}
	fa := &fakeAgent{}
	fa.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 先取覆盖体：pathBody 命中即以 200（或 pathStatus 指定码）回放，
		// 未被 pathStatus 覆盖的成功态路径也必须能读到自定义契约合法体。
		if body, hasBody := pathBody[r.URL.Path]; hasBody {
			code := http.StatusOK
			if c, ok := pathStatus[r.URL.Path]; ok {
				code = c
			}
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
			return
		}
		if code, ok := pathStatus[r.URL.Path]; ok {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		// 未命中路径：默认 200 + 契约合法的空 JSON object。
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(fa.srv.Close)
	return fa.srv.URL, fa
}

// serverNodesEnv 构造单节点 RUSTDESK_NODES（token ≥32 字符、URL 为纯 origin）。
func serverNodesEnv(agentURL string) string {
	nodes := []map[string]string{{
		"id": "node-a", "name": "Node A", "url": agentURL,
		"token": "0123456789abcdef0123456789abcdef",
	}}
	raw, err := json.Marshal(nodes)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// newServerMGMTContractServer 全栈契约服务器 + 已注册的假 agent 节点。
func newServerMGMTContractServer(t *testing.T, agentURL string) (*contractServer, *apptest.AppServer) {
	t.Helper()
	as := apptest.NewAppServer(t, func(cfg *config.Config) {
		cfg.RustdeskNodes = serverNodesEnv(agentURL)
	})
	cs := newContractServerWith(t, func() *server.Router {
		return server.NewRouter(server.RouterDeps{
			Logger:           testutil.TestLogger(),
			RateLimitEnabled: false,
			DB:               as.DB,
			Config:           as.Config,
		})
	})
	return cs, as
}

// TestContractServerMGMT 服务器域基础契约：认证挡 401、无节点配置时
// 列表 200 空数组、未注册节点转发 404（契约允许）。
func TestContractServerMGMT(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	token, _ := abLogin(t, cs)

	cs.get(t, "/api/servers", nil, http.StatusUnauthorized)
	cs.get(t, "/api/servers", bearer(token), http.StatusOK)
	cs.get(t, "/api/servers/ghost/peers", bearer(token), http.StatusNotFound)
	cs.get(t, "/api/servers/ghost/sessions", bearer(token), http.StatusNotFound)
	cs.get(t, "/api/servers/ghost/services/hbbs/config", bearer(token), http.StatusNotFound)
}

// TestContractServerMGMTListHandshake GET /api/servers 并发握手：
// 可达节点返回 reachable:true + services；api_version/node_id 不符时
// 视为不可达（行内标记，不整体失败）。
func TestContractServerMGMTListHandshake(t *testing.T) {
	agentURL, _ := newFakeAgent(t,
		map[string]int{"/v1/status": http.StatusOK},
		map[string]string{"/v1/status": `{"api_version":1,"node_id":"node-a","services":["hbbs","hbbr"]}`})
	cs, _ := newServerMGMTContractServer(t, agentURL)
	token, _ := abLogin(t, cs)

	raw := cs.get(t, "/api/servers", bearer(token), http.StatusOK)
	var nodes []map[string]any
	if err := json.Unmarshal(raw, &nodes); err != nil {
		t.Fatalf("servers body not array: %v (%s)", err, raw)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %s, want 1 element", raw)
	}
	if nodes[0]["id"] != "node-a" || nodes[0]["name"] != "Node A" {
		t.Errorf("node identity mismatch: %s", raw)
	}
	if reachable, _ := nodes[0]["reachable"].(bool); !reachable {
		t.Errorf("node should be reachable: %s", raw)
	}
	if svc, ok := nodes[0]["services"].([]any); !ok || len(svc) != 2 {
		t.Errorf("services = %v, want 2 entries", nodes[0]["services"])
	}
}

// TestContractServerMGMTListUnreachable 不可达节点仅在行内标记
// reachable:false 且 services 为空数组，接口整体仍 200。
func TestContractServerMGMTListUnreachable(t *testing.T) {
	cs, _ := newServerMGMTContractServer(t, "http://127.0.0.1:1")
	token, _ := abLogin(t, cs)

	raw := cs.get(t, "/api/servers", bearer(token), http.StatusOK)
	var nodes []map[string]any
	if err := json.Unmarshal(raw, &nodes); err != nil {
		t.Fatalf("servers body not array: %v (%s)", err, raw)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %s, want 1 element", raw)
	}
	if reachable, _ := nodes[0]["reachable"].(bool); reachable {
		t.Errorf("node on closed port must be unreachable: %s", raw)
	}
	if svc, ok := nodes[0]["services"].([]any); !ok || len(svc) != 0 {
		t.Errorf("unreachable node services must be empty array: %s", raw)
	}
}

// TestContractServerMGMTListVersionMismatch api_version ≠ 1 或 node_id
// 与注册 id 不符 → 视为不可达（事实③握手校验）。
func TestContractServerMGMTListVersionMismatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"bad api_version", `{"api_version":2,"node_id":"node-a","services":[]}`},
		{"bad node_id", `{"api_version":1,"node_id":"someone-else","services":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agentURL, _ := newFakeAgent(t,
				map[string]int{"/v1/status": http.StatusOK},
				map[string]string{"/v1/status": tc.body})
			cs, _ := newServerMGMTContractServer(t, agentURL)
			token, _ := abLogin(t, cs)
			raw := cs.get(t, "/api/servers", bearer(token), http.StatusOK)
			var nodes []map[string]any
			if err := json.Unmarshal(raw, &nodes); err != nil {
				t.Fatalf("body not array: %v (%s)", err, raw)
			}
			if len(nodes) != 1 {
				t.Fatalf("nodes = %s", raw)
			}
			if reachable, _ := nodes[0]["reachable"].(bool); reachable {
				t.Errorf("mismatched handshake must be unreachable: %s", raw)
			}
		})
	}
}

// TestContractServerMGMTErrorMatrix 错误映射矩阵端到端逐条锁定
// （共享知识 16 / 事实③）：假 agent 状态码 → 映射后的状态码与固定文案。
func TestContractServerMGMTErrorMatrix(t *testing.T) {
	cases := []struct {
		name       string
		upstream   int
		body       string
		wantStatus int
		wantMsg    string
	}{
		{"agent400→400", 400, `{}`, http.StatusBadRequest, "Invalid server management request"},
		{"agent404→404", 404, `{}`, http.StatusNotFound, "Server resource not found"},
		{"agent409→400", 409, `{}`, http.StatusBadRequest, "Server configuration conflicts"},
		{"agent504→504", 504, `{}`, http.StatusGatewayTimeout, "Server management operation timed out"},
		{"agent500→502", 500, `{}`, http.StatusBadGateway, "Server management operation failed"},
		{"agent503→502", 503, `{}`, http.StatusBadGateway, "Server management operation failed"},
		{"nonJSON→502", 200, `not json at all`, http.StatusBadGateway, "Invalid node management response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agentURL, _ := newFakeAgent(t,
				map[string]int{"/v1/peers": tc.upstream},
				map[string]string{"/v1/peers": tc.body})
			cs, _ := newServerMGMTContractServer(t, agentURL)
			token, _ := abLogin(t, cs)
			raw := cs.get(t, "/api/servers/node-a/peers", bearer(token), tc.wantStatus)
			assertEnvelopeMessage(t, raw, tc.wantStatus, tc.wantMsg)
		})
	}
}

// TestContractServerMGMTNetworkError agent 不可达 → 503 Server node unavailable。
func TestContractServerMGMTNetworkError(t *testing.T) {
	cs, _ := newServerMGMTContractServer(t, "http://127.0.0.1:1")
	token, _ := abLogin(t, cs)
	raw := cs.get(t, "/api/servers/node-a/peers", bearer(token), http.StatusServiceUnavailable)
	assertEnvelopeMessage(t, raw, http.StatusServiceUnavailable, "Server node unavailable")
}

// TestContractServerMGMTUnregisteredNode 未注册节点 id → 404（转发器
// ErrNodeNotFound，不触达任何 agent）。
func TestContractServerMGMTUnregisteredNode(t *testing.T) {
	agentURL, _ := newFakeAgent(t, nil, nil)
	cs, _ := newServerMGMTContractServer(t, agentURL)
	token, _ := abLogin(t, cs)
	for _, path := range []string{
		"/api/servers/ghost/peers",
		"/api/servers/ghost/sessions",
		"/api/servers/ghost/services/hbbs/config",
		"/api/servers/ghost/services/hbbs/logs",
		"/api/servers/ghost/bans",
	} {
		cs.get(t, path, bearer(token), http.StatusNotFound)
	}
}

// TestContractServerMGMTForwardPassthrough 成功态：上游 JSON 原样透传，
// 且各转发端点契约双向合法。
func TestContractServerMGMTForwardPassthrough(t *testing.T) {
	agentURL, _ := newFakeAgent(t, nil, map[string]string{
		"/v1/bans":                 `{"device_ids":["d1"],"ips":["10.0.0.1"]}`,
		"/v1/services/hbbs/config": `{"values":{"relay-servers":"hbbr.example"}}`,
		"/v1/services/hbbr/config": `{"values":{"relay-servers":"hbbr.example"}}`,
		"/v1/services/hbbr/action": `{"status":"ok","action":"start"}`,
		"/v1/services/hbbs/action": `{"status":"ok","action":"start"}`,
		"/v1/sessions/sess-1":      `{}`,
	})
	cs, _ := newServerMGMTContractServer(t, agentURL)
	token, _ := abLogin(t, cs)

	raw := cs.get(t, "/api/servers/node-a/peers", bearer(token), http.StatusOK)
	if string(raw) != `{"ok":true}` {
		t.Errorf("peers passthrough = %s, want upstream body", raw)
	}
	cs.get(t, "/api/servers/node-a/sessions", bearer(token), http.StatusOK)
	cs.get(t, "/api/servers/node-a/services/hbbs/logs", bearer(token), http.StatusOK)
	cs.get(t, "/api/servers/node-a/bans", bearer(token), http.StatusOK)

	cs.get(t, "/api/servers/node-a/services/hbbs/config", bearer(token), http.StatusOK)
	cs.put(t, "/api/servers/node-a/services/hbbs/config",
		map[string]any{"values": map[string]string{"relay-servers": "hbbr.example"}},
		bearer(token), http.StatusOK)

	for _, action := range []string{"start", "stop", "restart", "apply"} {
		cs.post(t, "/api/servers/node-a/services/hbbr/"+action, nil, bearer(token), http.StatusOK)
	}

	cs.delete(t, "/api/servers/node-a/sessions/sess-1", bearer(token), http.StatusOK)
}

// TestContractServerMGMTEnumValidation 路径枚举违例 → 400（service ∉
// hbbs|hbbr 由契约枚举与面板侧双重拦截）。
func TestContractServerMGMTEnumValidation(t *testing.T) {
	agentURL, _ := newFakeAgent(t, nil, nil)
	cs, _ := newServerMGMTContractServer(t, agentURL)
	token, _ := abLogin(t, cs)

	cs.invalid(t, http.MethodGet, "/api/servers/node-a/services/mysql/config", nil,
		bearer(token), http.StatusBadRequest)
	cs.invalid(t, http.MethodGet, "/api/servers/node-a/services/mysql/logs", nil,
		bearer(token), http.StatusBadRequest)
}

// TestContractServerMGMTBansValidation PUT bans 载荷形状：非法 IPv4 →
// 400（契约 format: ipv4 与面板侧 ValidateBans 双防线）；合法载荷透传。
func TestContractServerMGMTBansValidation(t *testing.T) {
	agentURL, _ := newFakeAgent(t, nil, nil)
	cs, _ := newServerMGMTContractServer(t, agentURL)
	token, _ := abLogin(t, cs)

	cs.invalid(t, http.MethodPut, "/api/servers/node-a/bans",
		map[string]any{"device_ids": []string{"d1"}, "ips": []string{"999.1.1.1"}},
		bearer(token), http.StatusBadRequest)

	cs.put(t, "/api/servers/node-a/bans",
		map[string]any{"device_ids": []string{"d1", "d2"}, "ips": []string{"10.0.0.1", "192.168.1.1"}},
		bearer(token), http.StatusOK)
}

// TestContractServerMGMTUnauthorized 未认证 → 401（servers.* 五档均需 JWT）。
func TestContractServerMGMTUnauthorized(t *testing.T) {
	agentURL, _ := newFakeAgent(t, nil, nil)
	cs, _ := newServerMGMTContractServer(t, agentURL)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/servers"},
		{http.MethodGet, "/api/servers/node-a/peers"},
		{http.MethodGet, "/api/servers/node-a/sessions"},
		{http.MethodDelete, "/api/servers/node-a/sessions/sess-1"},
		{http.MethodGet, "/api/servers/node-a/services/hbbs/config"},
		{http.MethodPut, "/api/servers/node-a/services/hbbs/config"},
		{http.MethodGet, "/api/servers/node-a/services/hbbs/logs"},
		{http.MethodPost, "/api/servers/node-a/services/hbbs/start"},
		{http.MethodGet, "/api/servers/node-a/bans"},
		{http.MethodPut, "/api/servers/node-a/bans"},
	} {
		// 请求体须先满足 openapi 形状，否则在校验层即被拦截，
		// 无法证明「未认证 → 401」这一鉴权语义。
		var body any
		switch {
		case tc.path == "/api/servers/node-a/bans" && tc.method == http.MethodPut:
			body = map[string]any{"device_ids": []string{"d1"}, "ips": []string{"10.0.0.1"}}
		case tc.method == http.MethodPut:
			body = map[string]any{"values": map[string]string{}}
		}
		cs.raw(t, tc.method, tc.path, body, nil, http.StatusUnauthorized)
	}
}

// TestContractServerMGMTEmptyNodeConfig RUSTDESK_NODES 未配置时列表返回
// 200 空数组（非 500）。
func TestContractServerMGMTEmptyNodeConfig(t *testing.T) {
	as := apptest.NewAppServer(t, nil)
	cs := newContractServerWith(t, func() *server.Router {
		return server.NewRouter(server.RouterDeps{
			Logger:           testutil.TestLogger(),
			RateLimitEnabled: false,
			DB:               as.DB,
			Config:           as.Config,
		})
	})
	token, _ := abLogin(t, cs)
	raw := cs.get(t, "/api/servers", bearer(token), http.StatusOK)
	var nodes []map[string]any
	if err := json.Unmarshal(raw, &nodes); err != nil {
		t.Fatalf("servers body not array: %v (%s)", err, raw)
	}
	if len(nodes) != 0 {
		t.Errorf("unconfigured nodes should yield empty array: %s", raw)
	}
}
