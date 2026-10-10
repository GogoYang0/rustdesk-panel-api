package contract

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestSpecLoadsAndCounts 验证 spec 可加载、可校验且 path/操作数与
// 当前里程碑范围一致：M1 25 + M2 43 + M3 96 = 164 操作，GAP2 增量 8
// （assign / me-devices / user-devices / mfa enroll ×2 / settings-mfa
// GET+PUT / audits/login）= 172 操作；137 个 path key（GAP2 设计
// §2.3/§3 增 7 条 path）。
func TestSpecLoadsAndCounts(t *testing.T) {
	doc := loadSpec(t)
	if got := doc.Paths.Len(); got != 137 {
		t.Fatalf("openapi paths = %d, want 137", got)
	}
	ops := 0
	for _, item := range doc.Paths.Map() {
		ops += len(item.Operations())
	}
	if ops != 172 {
		t.Fatalf("openapi operations = %d, want 172", ops)
	}
	for _, p := range []string{
		"/api/healthz", "/api/login", "/api/login-options", "/api/logout",
		"/api/currentUser", "/api/2fa/setup", "/api/2fa/verify", "/api/2fa",
		"/api/passkey/register/begin", "/api/passkey/register/verify",
		"/api/passkey/auth/begin", "/api/passkey/auth/verify",
		"/api/passkey/list", "/api/passkey/{guid}", "/api/passkey/tfa",
		"/api/sessions", "/api/sessions/{jti}",
		"/api/oidc/auth", "/api/oidc/auth-query", "/api/oidc/callback",
		"/api/users/me", "/api/users/me/password", "/api/users/me/avatar",
		"/api/avatars/{filename}",
		// M2 路径抽查（域级覆盖见 m2 契约测试）。
		"/api/heartbeat", "/api/sysinfo", "/api/peers", "/api/devices",
		"/api/devices/status", "/api/devices/{guid}", "/api/devices/{uuid}/disconnect",
		"/api/device-group/accessible", "/api/device-groups", "/api/device-groups/strategy-targets",
		"/api/device-groups/{guid}", "/api/device-groups/{guid}/devices",
		"/api/strategies", "/api/strategies/candidates", "/api/strategies/target-candidates",
		"/api/strategies/{guid}", "/api/strategies/{guid}/assignments",
		"/api/strategies/{guid}/assign", "/api/strategies/{guid}/unassign",
		"/api/permissions", "/api/permissions/me", "/api/roles", "/api/roles/{guid}",
		"/api/roles/{guid}/protection-impact", "/api/users/{guid}/roles",
		"/api/users/{guid}/roles/eligibility", "/api/user-groups",
		"/api/user-groups/{guid}", "/api/user-groups/{guid}/users",
	} {
		if doc.Paths.Find(p) == nil {
			t.Errorf("path %s missing in spec", p)
		}
	}
}

// TestHealthzContract healthz 首个契约用例：请求/响应双向校验通过。
func TestHealthzContract(t *testing.T) {
	cs := newContractServer(t)
	body := cs.get(t, "/api/healthz", nil, http.StatusOK)

	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %v, want ok", resp["status"])
	}
}

// TestTamperedResponseFails 篡改响应（缺 required 字段 status）必须校验失败，
// 证明校验器真实生效（设计 T02 验收）。
func TestTamperedResponseFails(t *testing.T) {
	cs := newContractServer(t)

	req, err := http.NewRequest(http.MethodGet, "http://localhost/api/healthz", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if verr := cs.validatePair(req, http.StatusOK, http.Header{}, []byte(`{"oops":1}`)); verr == nil {
		t.Fatal("tampered response should violate the contract, but validation passed")
	}
}

// TestUnknownRouteRejected 不在 spec 中的方法/路径组合必须被路由拒绝。
func TestUnknownRouteRejected(t *testing.T) {
	cs := newContractServer(t)

	req, err := http.NewRequest(http.MethodPost, "http://localhost/api/healthz", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if verr := cs.validatePair(req, http.StatusOK, http.Header{}, []byte(`{}`)); verr == nil {
		t.Fatal("POST /api/healthz should not match any spec route")
	}
}
