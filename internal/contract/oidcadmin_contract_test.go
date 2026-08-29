// oidcadmin_contract_test.go OIDC 提供者域（M3 T07，事实⑧）8 端点契约用例：
// 以 openapi.yaml 为准绳做请求/响应双向校验，并锁定 sort 数组语义
// （guid 数组顺序即 priority）、clientSecret 明文可见、POST=200、
// 删除固定文案 'OIDC provider deleted'、重名 400。
package contract

import (
	"encoding/json"
	"net/http"
	"testing"
)

// oidcProviderCreate 创建提供者并返回 guid（断言 POST 返回 200）。
func oidcProviderCreate(t *testing.T, cs *contractServer, token, name, issuer string) string {
	t.Helper()
	raw := cs.post(t, "/api/oidc-providers", map[string]any{
		"name":         name,
		"issuer":       issuer,
		"clientId":     "client-" + name,
		"clientSecret": "secret-" + name,
	}, bearer(token), http.StatusOK)
	var view struct {
		Guid string `json:"guid"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("provider body not object: %v (%s)", err, raw)
	}
	if view.Guid == "" {
		t.Fatalf("provider guid empty: %s", raw)
	}
	return view.Guid
}

// TestContractOidcProvidersCRUD 列表/创建/详情/更新/删除全链。
func TestContractOidcProvidersCRUD(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	token, _ := abLogin(t, cs)

	// 空列表：{data:[], total:0}。
	raw := cs.get(t, "/api/oidc-providers", bearer(token), http.StatusOK)
	var page struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("provider page not object: %v (%s)", err, raw)
	}
	if len(page.Data) != 0 || page.Total != 0 {
		t.Errorf("initial page = %s, want empty", raw)
	}

	guid := oidcProviderCreate(t, cs, token, "corp-oidc", "https://idp.example")

	// 详情：clientSecret 明文可见（设计事实⑧，参考即如此）。
	raw = cs.get(t, "/api/oidc-providers/"+guid, bearer(token), http.StatusOK)
	var view struct {
		Guid         string `json:"guid"`
		Type         string `json:"type"`
		Scope        string `json:"scope"`
		Enabled      bool   `json:"enabled"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("provider detail not object: %v (%s)", err, raw)
	}
	if view.ClientSecret != "secret-corp-oidc" {
		t.Errorf("clientSecret must be plaintext for admin: %s", raw)
	}
	// 缺省值：type=oidc、scope=openid email profile、enabled=true。
	if view.Type != "oidc" {
		t.Errorf("default type = %q, want oidc", view.Type)
	}
	if view.Scope != "openid email profile" {
		t.Errorf("default scope = %q, want oidc default", view.Scope)
	}
	if !view.Enabled {
		t.Errorf("default enabled = false, want true")
	}

	// 部分更新。
	cs.patch(t, "/api/oidc-providers/"+guid, map[string]any{
		"name": "corp-oidc", "issuer": "https://idp2.example",
		"clientId": "c2", "clientSecret": "s2",
		"scope": "openid email", "enabled": false, "priority": 5,
	}, bearer(token), http.StatusOK)

	// 重名 400。
	oidcProviderCreate(t, cs, token, "second", "https://idp3.example")
	cs.post(t, "/api/oidc-providers", map[string]any{
		"name": "second", "issuer": "https://idp4.example",
		"clientId": "c", "clientSecret": "s",
	}, bearer(token), http.StatusBadRequest)

	// 删除 → 固定文案。
	raw = cs.delete(t, "/api/oidc-providers/"+guid, bearer(token), http.StatusOK)
	var deleted struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &deleted); err != nil {
		t.Fatalf("delete body not object: %v (%s)", err, raw)
	}
	if deleted.Message != "OIDC provider deleted" {
		t.Errorf("delete message = %q, want 'OIDC provider deleted' (%s)", deleted.Message, raw)
	}

	// 已删详情 → 404。
	cs.get(t, "/api/oidc-providers/"+guid, bearer(token), http.StatusNotFound)
	// 未知 guid 详情 → 404。
	cs.get(t, "/api/oidc-providers/no-such-guid", bearer(token), http.StatusNotFound)
}

// TestContractOidcProviderSortAndToggle sort 数组语义（顺序即 priority）
// 与 toggle 启停切换。
func TestContractOidcProviderSortAndToggle(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	token, _ := abLogin(t, cs)

	first := oidcProviderCreate(t, cs, token, "alpha", "https://a.example")
	second := oidcProviderCreate(t, cs, token, "beta", "https://b.example")

	// sort：库内插入顺序为 alpha(0) → beta(1)；反序重排后 beta=0、alpha=1。
	cs.patch(t, "/api/oidc-providers/sort", []string{second, first}, bearer(token), http.StatusOK)

	raw := cs.get(t, "/api/oidc-providers", bearer(token), http.StatusOK)
	var page struct {
		Data []struct {
			Name     string `json:"name"`
			Priority int    `json:"priority"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("provider page not object: %v (%s)", err, raw)
	}
	if len(page.Data) != 2 {
		t.Fatalf("page = %s, want 2 providers", raw)
	}
	if page.Data[0].Name != "beta" || page.Data[0].Priority != 0 {
		t.Errorf("sort not applied (priority ASC): %s", raw)
	}
	if page.Data[1].Name != "alpha" || page.Data[1].Priority != 1 {
		t.Errorf("sort not applied (priority ASC): %s", raw)
	}

	// 空数组 → 400（不允许清空排序）。
	cs.invalid(t, http.MethodPatch, "/api/oidc-providers/sort", []string{},
		bearer(token), http.StatusBadRequest)

	// toggle：创建缺省 enabled=true，切换后 false，再切回 true。
	raw = cs.patch(t, "/api/oidc-providers/"+first+"/toggle", nil, bearer(token), http.StatusOK)
	var toggled struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &toggled); err != nil {
		t.Fatalf("toggle body not object: %v (%s)", err, raw)
	}
	if toggled.Enabled {
		t.Errorf("first toggle should disable provider: %s", raw)
	}
	raw = cs.patch(t, "/api/oidc-providers/"+first+"/toggle", nil, bearer(token), http.StatusOK)
	if err := json.Unmarshal(raw, &toggled); err != nil {
		t.Fatalf("second toggle body not object: %v (%s)", err, raw)
	}
	if !toggled.Enabled {
		t.Errorf("second toggle should re-enable provider: %s", raw)
	}

	// 未知 guid toggle → 404。
	cs.patch(t, "/api/oidc-providers/no-such-guid/toggle", nil, bearer(token), http.StatusNotFound)
}

// TestContractOidcProviderTest discovery 测试恒 200
// {success,message,endpoints?}（provider 存在但 issuer 不可达 → success:false）。
func TestContractOidcProviderTest(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	token, _ := abLogin(t, cs)

	guid := oidcProviderCreate(t, cs, token, "unreachable", "http://127.0.0.1:1")
	raw := cs.post(t, "/api/oidc-providers/"+guid+"/test", nil, bearer(token), http.StatusOK)
	var result struct {
		Success   bool            `json:"success"`
		Message   string          `json:"message"`
		Endpoints *map[string]any `json:"endpoints,omitempty"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("oidc test body not object: %v (%s)", err, raw)
	}
	if result.Success {
		t.Errorf("discovery against unreachable issuer must be success:false: %s", raw)
	}
	if result.Message == "" {
		t.Errorf("oidc test message must be non-empty: %s", raw)
	}

	// 未知 guid → 404（provider 不存在不是 success:false）。
	cs.post(t, "/api/oidc-providers/no-such-guid/test", nil, bearer(token), http.StatusNotFound)
}

// TestContractOidcProvidersUnauthorized 未认证 → 401（8 档均 AdminGuard）。
func TestContractOidcProvidersUnauthorized(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/oidc-providers", nil},
		{http.MethodPost, "/api/oidc-providers", map[string]any{
			"name": "x", "issuer": "https://x.example", "clientId": "c", "clientSecret": "s"}},
		{http.MethodPatch, "/api/oidc-providers/sort", []string{"g"}},
		{http.MethodGet, "/api/oidc-providers/guid-1", nil},
		{http.MethodPatch, "/api/oidc-providers/guid-1", map[string]any{
			"name": "x", "issuer": "https://x.example", "clientId": "c", "clientSecret": "s"}},
		{http.MethodDelete, "/api/oidc-providers/guid-1", nil},
		{http.MethodPatch, "/api/oidc-providers/guid-1/toggle", nil},
		{http.MethodPost, "/api/oidc-providers/guid-1/test", nil},
	} {
		cs.raw(t, tc.method, tc.path, tc.body, nil, http.StatusUnauthorized)
	}
}
