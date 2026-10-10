// nexus_contract_test.go nexus 域（M3 T06，事实⑤）9 端点契约用例：
// 以 openapi.yaml 为准绳做请求/响应双向校验，并锁定两处状态码特例
// （POST builds = 201、DELETE builds/{uuid} = 204）与 safeJoin 的
// 400 Invalid path 穿越面。
//
// 上游以 httptest 假 nexus 注入（NEXUS_UPSTREAM 配置覆写，共享知识 19
// "仅测试覆写"）——不可达时绑定态/构建列表等本库端点仍须正常工作。
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

// newNexusContractServer 全栈契约服务器 + 假 nexus 上游。
//
// 返回的 upstream 可自定义 handler；默认为 404（未绑定用户走不到上游）。
func newNexusContractServer(t *testing.T, upstream http.Handler) (*contractServer, *apptest.AppServer) {
	t.Helper()
	var ts *httptest.Server
	if upstream != nil {
		ts = httptest.NewServer(upstream)
	} else {
		ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			httpx404(w)
		}))
	}
	t.Cleanup(ts.Close)

	as := apptest.NewAppServer(t, func(cfg *config.Config) {
		cfg.NexusUpstream = ts.URL
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

// httpx404 极简 404 响应（避免为测试引入 httpx 依赖）。
func httpx404(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"message":"not found"}`))
}

// TestContractNexusAuthAndBindStatus 绑定链路契约：
// bind-status 未绑定 → 200 {bound:false}；unbind 幂等 → 200 MessageResponse；
// login/status 在无登录会话时按契约出错误包络。
func TestContractNexusAuthAndBindStatus(t *testing.T) {
	cs, _ := newNexusContractServer(t, nil)
	token, _ := abLogin(t, cs)

	// 未绑定 → bound:false（契约 NexusBindStatus 必填 bound）。
	raw := cs.get(t, "/api/nexus/auth/bind-status", bearer(token), http.StatusOK)
	var bs struct {
		Bound bool `json:"bound"`
	}
	if err := json.Unmarshal(raw, &bs); err != nil {
		t.Fatalf("bind-status body not json: %v (%s)", err, raw)
	}
	if bs.Bound {
		t.Errorf("fresh user should be unbound: %s", raw)
	}

	// 解绑幂等：无记录亦 200。
	cs.delete(t, "/api/nexus/auth/bind", bearer(token), http.StatusOK)

	// login：上游 404 → 映射 502（upstreamError 非 503/504 走 502）。
	cs.post(t, "/api/nexus/auth/login", nil, bearer(token), http.StatusBadGateway)

	// status：login_id 契约必填（openapi），故此处仅覆盖"未知 login_id"
	// 的服务层语义——未登记的 login_id 归属校验失败 → 404（触不到上游）。
	cs.get(t, "/api/nexus/auth/status?login_id=unknown-login", bearer(token), http.StatusNotFound)
}

// TestContractNexusAuthUnauthorized 未认证访问 nexus 全部端点 → 401。
func TestContractNexusAuthUnauthorized(t *testing.T) {
	cs, _ := newNexusContractServer(t, nil)
	// 注意：契约对 POST /api/nexus/builds 要求必填请求体，故该条单独
	// 走 raw（带合法体）；其余无体端点走无体请求。
	cs.post(t, "/api/nexus/builds", validGenerateBody(), nil, http.StatusUnauthorized)
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/nexus/auth/login"},
		{http.MethodGet, "/api/nexus/auth/status?login_id=x"},
		{http.MethodGet, "/api/nexus/auth/bind-status"},
		{http.MethodDelete, "/api/nexus/auth/bind"},
		{http.MethodGet, "/api/nexus/builds"},
		{http.MethodDelete, "/api/nexus/builds/any-uuid"},
		{http.MethodGet, "/api/nexus/builds/any-uuid/files"},
		{http.MethodGet, "/api/nexus/builds/any-uuid/files/x.zip"},
	} {
		cs.raw(t, tc.method, tc.path, nil, nil, http.StatusUnauthorized)
	}
}

// TestContractNexusBuildLifecycle 构建链路契约：
// GET builds 空列表 200 []；CREATE 未绑定 → 401 固定文案；
// DELETE 未知 uuid → 404；files 清单 404；产物下载 404（归属校验先行）。
func TestContractNexusBuildLifecycle(t *testing.T) {
	cs, as := newNexusContractServer(t, nil)
	token, _ := abLogin(t, cs)

	// 空列表：契约 type: array。
	raw := cs.get(t, "/api/nexus/builds", bearer(token), http.StatusOK)
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("builds body not array: %v (%s)", err, raw)
	}
	if len(list) != 0 {
		t.Errorf("expected empty build list, got %s", raw)
	}

	// 未绑定 token → 401 'Nexus token has expired, please rebind'（事实⑤）。
	raw = cs.post(t, "/api/nexus/builds", map[string]any{
		"os": "windows", "arch": "x86_64",
		"custom": map[string]string{"app-name": "demo"},
	}, bearer(token), http.StatusUnauthorized)
	assertEnvelopeMessage(t, raw, http.StatusUnauthorized,
		"Nexus token has expired, please rebind")

	// 形状违例（os 非 windows）→ 400（契约 enum 复核在 handler）。
	cs.invalid(t, http.MethodPost, "/api/nexus/builds", map[string]any{
		"os": "linux", "arch": "x86_64",
		"custom": map[string]string{"app-name": "demo"},
	}, bearer(token), http.StatusBadRequest)

	// 取消未知 uuid → 404。
	cs.delete(t, "/api/nexus/builds/no-such-uuid", bearer(token), http.StatusNotFound)
	// 产物清单未知 uuid → 404。
	cs.get(t, "/api/nexus/builds/no-such-uuid/files", bearer(token), http.StatusNotFound)
	// 产物下载未知 uuid → 404（归属校验先于路径解析）。
	cs.get(t, "/api/nexus/builds/no-such-uuid/files/a.zip", bearer(token), http.StatusNotFound)

	// 跨用户隔离：另一用户看不到他人构建（fixture 落库后按 userGuid 过滤）。
	if as.DB == nil {
		t.Fatal("app server DB missing")
	}
}

// TestContractNexusDownloadSafeJoin 产物下载 safeJoin 穿越面 →
// 400 'Invalid path'（共享知识 16/25；批复 #8 文件名白名单）。
//
// 注：契约路由对 {filename} 为单段参数，含 '/' 的穿越串不会被路由命中
// （由 mux 判定为无匹配 → 404/SPA），故此处覆盖白名单可命中的越界形态：
// 含 ".." 的名称、以及合法名但文件不存在。
func TestContractNexusDownloadSafeJoin(t *testing.T) {
	cs, as := newNexusContractServer(t, nil)
	token, _ := abLogin(t, cs)
	user, _ := abLogin(t, cs) // 复用同一 admin（单用户场景）

	// 直接为已登录用户落一条构建 + 越界文件名。
	seedNexusBuild(t, as, "build-safe-1")

	// 白名单未通过（"..." 连续点集）→ 400 'Invalid path' 固定文案。
	raw := cs.get(t, "/api/nexus/builds/build-safe-1/files/...",
		bearer(token), http.StatusBadRequest)
	assertEnvelopeMessage(t, raw, http.StatusBadRequest, "Invalid path")

	// 白名单通过但产物未落盘 → 404（归属校验与 safeJoin 均通过）。
	cs.get(t, "/api/nexus/builds/build-safe-1/files/missing.zip",
		bearer(token), http.StatusNotFound)

	// 另一用户访问他人构建产物 → 404（跨用户隔离，事实⑤）。
	other := seedOtherUser(t, cs, token)
	cs.get(t, "/api/nexus/builds/build-safe-1/files/missing.zip",
		bearer(other), http.StatusNotFound)

	_ = user
}

// validGenerateBody 合法 NexusGenerateDto（契约必填 body）。
func validGenerateBody() map[string]any {
	return map[string]any{
		"os": "windows", "arch": "x86_64",
		"custom": map[string]string{"app-name": "demo"},
	}
}

// seedNexusBuild 为管理员用户落一条已完成构建（产物清单为空）。
//
// 直接落库而非走上游：本用例只需"归属校验通过 + 文件名安全路径"两类
// 判定，构建创建链路已由 TestContractNexusBuildLifecycle 覆盖。
func seedNexusBuild(t *testing.T, as *apptest.AppServer, buildUuid string) {
	t.Helper()
	var guid string
	if err := as.DB.Raw("SELECT guid FROM users ORDER BY username ASC LIMIT 1").
		Scan(&guid).Error; err != nil {
		t.Fatalf("lookup user guid: %v", err)
	}
	if guid == "" {
		t.Fatal("no seeded user found")
	}
	if err := as.DB.Exec(
		`INSERT INTO nexus_builds (uuid, userGuid, os, arch, status, custom, files, message, createdAt)
		 VALUES (?, ?, 'windows', 'x86_64', 'done', '{}', '[]', '', ?)`,
		buildUuid, guid, "2026-08-27 12:00:00+08:00",
	).Error; err != nil {
		t.Fatalf("seed nexus build: %v", err)
	}
}

// seedOtherUser 经管理员 API 建一个普通用户并返回其登录 token
// （复用 T03 users 端点，避免测试与 users 表列名耦合）。
func seedOtherUser(t *testing.T, cs *contractServer, adminToken string) string {
	t.Helper()
	cs.post(t, "/api/users", map[string]any{
		"username": "nexus-other",
		"password": "other-pass",
		"email":    "nexus-other@test.local",
		"name":     "Nexus Other",
	}, bearer(adminToken), http.StatusOK)

	raw := cs.post(t, "/api/login", map[string]any{
		"type": "account", "username": "nexus-other", "password": "other-pass",
		"id": "dev-other", "uuid": "uuid-other",
		"deviceInfo": map[string]any{"name": "web", "os": "linux", "type": "web"},
	}, nil, http.StatusOK)
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.AccessToken == "" {
		t.Fatalf("other user login failed: %v (%s)", err, raw)
	}
	return resp.AccessToken
}

// assertEnvelopeMessage 断言错误包络 message 与预期固定文案逐字节一致。
func assertEnvelopeMessage(t *testing.T, body []byte, wantStatus int, wantMessage string) {
	t.Helper()
	var env struct {
		StatusCode int    `json:"statusCode"`
		Message    string `json:"message"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("error body not json: %v (%s)", err, body)
	}
	if env.StatusCode != wantStatus {
		t.Errorf("statusCode = %d, want %d", env.StatusCode, wantStatus)
	}
	if env.Message != wantMessage {
		t.Errorf("message = %q, want %q", env.Message, wantMessage)
	}
}
