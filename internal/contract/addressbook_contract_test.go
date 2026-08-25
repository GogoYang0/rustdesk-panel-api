// addressbook_contract_test.go 通讯录域（M3 T05，事实⑦）32 端点契约用例：
// 以 openapi.yaml 为准绳，对全部 32 个 operationId 做请求/响应双向校验。
// 兼容怪癖三件套（GET 空 'null' / POST 成功 'null' + 失败 {error}200 /
// settings 恒 max_peer_one_ab=0）逐字节行为在 internal/qa/m3_compat_test.go
// 单独字节级锁定；本文件聚焦"每个端点 200/预期状态 + 双向契约合法"。
package contract

import (
	"encoding/json"
	"net/http"
	"testing"
)

// put PUT 便捷封装（contractServer 基类未提供）。
func (cs *contractServer) put(t *testing.T, path string, body any, headers map[string]string, expectStatus int) []byte {
	return cs.raw(t, http.MethodPut, path, body, headers, expectStatus)
}

// deleteBody DELETE 带 body 便捷封装（contractServer.delete 仅支持无 body）。
func (cs *contractServer) deleteBody(t *testing.T, path string, body any, headers map[string]string, expectStatus int) []byte {
	return cs.raw(t, http.MethodDelete, path, body, headers, expectStatus)
}

// abLogin 登录并返回 token 与 admin guid（全栈契约服务器）。
func abLogin(t *testing.T, cs *contractServer) (string, string) {
	t.Helper()
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)
	user, _ := login["user"].(map[string]any)
	guid, _ := user["guid"].(string)
	if guid == "" {
		t.Fatal("admin guid missing")
	}
	return token, guid
}

// guidFromRef 从 AddressBookRef 响应提取 guid。
func guidFromRef(t *testing.T, raw []byte) string {
	t.Helper()
	var ref struct {
		Guid string `json:"guid"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &ref); err != nil {
		t.Fatalf("parse AddressBookRef: %v (%s)", err, raw)
	}
	if ref.Guid == "" {
		t.Fatalf("AddressBookRef.guid empty: %s", raw)
	}
	return ref.Guid
}

// TestContractAddressBook32 通讯录域全 32 端点契约双向校验。
func TestContractAddressBook32(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	token, adminGuid := abLogin(t, cs)

	// ---- personal 双端点（幂等取/建）----
	raw := cs.get(t, "/api/ab/personal", bearer(token), 200)
	customRef := guidFromRef(t, raw)
	_ = cs.post(t, "/api/ab/personal", nil, bearer(token), 200)

	// ---- legacy 双端点（兼容怪癖；字节级在 qa 锁定，此处只验契约）----
	cs.get(t, "/api/ab", bearer(token), 200)
	cs.post(t, "/api/ab", map[string]any{"data": "{\"tags\":[],\"peers\":[],\"tag_colors\":\"\"}"}, bearer(token), 200)
	// 失败形态：data 内 JSON 非法 → {error} 且 HTTP 200（仅此端点）。
	cs.post(t, "/api/ab", map[string]any{"data": "{not-valid-json"}, bearer(token), 200)

	// ---- ab/settings（恒 max_peer_one_ab=0）----
	raw = cs.post(t, "/api/ab/settings", nil, bearer(token), 200)
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatalf("settings body: %v (%s)", err, raw)
	}
	if settings["max_peer_one_ab"] != float64(0) {
		t.Errorf("max_peer_one_ab = %v, want 0", settings["max_peer_one_ab"])
	}

	// ---- custom 端点 ----
	raw = cs.post(t, "/api/ab/custom/add", map[string]any{"name": "m3-custom-book"}, bearer(token), 200)
	customBook := guidFromRef(t, raw)
	_ = customRef
	cs.get(t, "/api/ab/custom/profiles", bearer(token), 200)
	cs.put(t, "/api/ab/custom/update/profile",
		map[string]any{"guid": customBook, "name": "m3-custom-book-renamed"}, bearer(token), 200)

	// ---- custom 书内 peers / tags / peer / tag 全链 ----
	cs.get(t, "/api/ab/peers?ab="+customBook, bearer(token), 200)
	cs.post(t, "/api/ab/peers", map[string]any{"ab": customBook}, bearer(token), 200)
	raw = cs.get(t, "/api/ab/tags/"+customBook, bearer(token), 200)
	var tagList struct {
		Data []struct {
			Guid string `json:"guid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &tagList); err != nil {
		t.Fatalf("tags list: %v (%s)", err, raw)
	}
	cs.post(t, "/api/ab/tags/"+customBook,
		map[string]any{"tags": []map[string]any{{"name": "ct1", "color": 0}}}, bearer(token), 200)

	raw = cs.post(t, "/api/ab/peer/add/"+customBook,
		map[string]any{"id": "m3-dev-y", "alias": "m3-alias"}, bearer(token), 200)
	var abPeer struct {
		Guid string `json:"guid"`
	}
	if err := json.Unmarshal(raw, &abPeer); err != nil || abPeer.Guid == "" {
		t.Fatalf("ab peer add: %v (%s)", err, raw)
	}
	cs.put(t, "/api/ab/peer/update/"+abPeer.Guid,
		map[string]any{"id": "m3-dev-y", "alias": "m3-alias-2"}, bearer(token), 200)
	cs.delete(t, "/api/ab/peer/"+abPeer.Guid, bearer(token), 200)

	raw = cs.post(t, "/api/ab/tag/add/"+customBook,
		map[string]any{"name": "m3-tag", "color": 0}, bearer(token), 200)
	var abTag struct {
		Guid string `json:"guid"`
	}
	if err := json.Unmarshal(raw, &abTag); err != nil || abTag.Guid == "" {
		t.Fatalf("ab tag add: %v (%s)", err, raw)
	}
	cs.put(t, "/api/ab/tag/rename/"+abTag.Guid,
		map[string]any{"name": "m3-tag-renamed"}, bearer(token), 200)
	cs.put(t, "/api/ab/tag/update/"+abTag.Guid,
		map[string]any{"name": "m3-tag-renamed", "color": 1}, bearer(token), 200)
	cs.delete(t, "/api/ab/tag/"+abTag.Guid, bearer(token), 200)

	// ---- custom 书规则链（owner → FULL_CONTROL）----
	cs.get(t, "/api/ab/rules", bearer(token), 200)
	raw = cs.post(t, "/api/ab/rule",
		map[string]any{"guid": customBook, "rule": 1, "user": adminGuid}, bearer(token), 200)
	var abRule struct {
		Guid string `json:"guid"`
	}
	if err := json.Unmarshal(raw, &abRule); err != nil || abRule.Guid == "" {
		t.Fatalf("ab rule create: %v (%s)", err, raw)
	}
	cs.patch(t, "/api/ab/rule",
		map[string]any{"guid": abRule.Guid, "rule": 2}, bearer(token), 200)
	cs.deleteBody(t, "/api/ab/rules", map[string]any{"guids": []string{abRule.Guid}}, bearer(token), 200)

	// ---- custom 书删除（事务级联）----
	cs.deleteBody(t, "/api/ab/custom", map[string]any{"guids": []string{customBook}}, bearer(token), 200)

	// ---- shared 端点 ----
	raw = cs.post(t, "/api/ab/shared/add", map[string]any{"name": "m3-shared-book"}, bearer(token), 200)
	sharedBook := guidFromRef(t, raw)
	cs.get(t, "/api/ab/shared/profiles", bearer(token), 200)
	cs.post(t, "/api/ab/shared/profiles", map[string]any{"current": 1, "pageSize": 10}, bearer(token), 200)
	cs.get(t, "/api/ab/shared/list", bearer(token), 200)
	cs.get(t, "/api/ab/shared/"+sharedBook+"/access", bearer(token), 200)
	cs.get(t, "/api/ab/shared/"+sharedBook+"/share-candidates", bearer(token), 200)
	cs.put(t, "/api/ab/shared/update/profile",
		map[string]any{"guid": sharedBook, "name": "m3-shared-book-renamed"}, bearer(token), 200)
	cs.deleteBody(t, "/api/ab/shared", map[string]any{"guids": []string{sharedBook}}, bearer(token), 200)
}

// TestContractAddressBookAuth401 通讯录域 GET 受保护端点未认证 → 401 包络。
// （POST/PUT/DELETE 受保护端点均带 required body，未认证请求无 body 会先
// 触发契约请求校验失败，故 401 专项仅覆盖 GET 端点。）
func TestContractAddressBookAuth401(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	for _, path := range []string{
		"/api/ab",
		"/api/ab/personal",
		"/api/ab/custom/profiles",
		"/api/ab/shared/profiles",
		"/api/ab/shared/list",
		"/api/ab/rules",
	} {
		raw := cs.raw(t, http.MethodGet, path, nil, nil, 401)
		assertEnvelopeShape(t, raw, 401)
	}
}

// TestContractAddressBookConflict 重名 custom 书 → 409 固定文案（message 为纯文本）。
func TestContractAddressBookConflict(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	token, _ := abLogin(t, cs)
	cs.post(t, "/api/ab/custom/add", map[string]any{"name": "dup-book"}, bearer(token), 200)
	raw := cs.post(t, "/api/ab/custom/add", map[string]any{"name": "dup-book"}, bearer(token), 409)
	assertEnvelopeShape(t, raw, 409)
	var env struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("409 body not json: %v (%s)", err, raw)
	}
	if env.Message != "Address book name already exists" {
		t.Errorf("message = %q, want %q", env.Message, "Address book name already exists")
	}
}
