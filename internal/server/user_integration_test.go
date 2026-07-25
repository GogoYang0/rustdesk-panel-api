// user_integration_test.go 用户自身端点集成测试：
// 资料更新/改密/头像上传删除/静态服务与防穿越（T05 场景）。
package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// webpPayload 构造带 RIFF/WEBP 魔数的最小"图片"。
func webpPayload() []byte {
	b := make([]byte, 40)
	copy(b[0:4], "RIFF")
	copy(b[8:12], "WEBP")
	return b
}

// pngPayload 非 webp 数据（嗅探必须拒绝）。
func pngPayload() []byte {
	return []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 'I', 'H', 'D', 'R'}
}

// uploadAvatar 以 multipart 表单上传头像，返回状态码与解析 map。
func uploadAvatar(t *testing.T, ts *apptest.AppServer, token string, payload []byte) (int, map[string]any) {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("avatar", "avatar.webp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.TS.URL+"/api/users/me/avatar", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.TS.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	parsed := map[string]any{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("upload avatar body not json: %s", raw)
	}
	return resp.StatusCode, parsed
}

// ---- 资料更新 ----

// TestUpdateMeSuccess 三字段更新生效且返回更新后的 payload。
func TestUpdateMeSuccess(t *testing.T) {
	ts := newAuthServerNoLimit(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPatch, ts.TS.URL+"/api/users/me",
		map[string]any{"display_name": "Admin", "email": "admin@example.com", "note": "keeper"}, authHeader(token))
	if status != 200 {
		t.Fatalf("update me status = %d: %s", status, raw)
	}
	if parsed["display_name"] != "Admin" || parsed["email"] != "admin@example.com" || parsed["note"] != "keeper" {
		t.Errorf("payload = %v", parsed)
	}
}

// TestUpdateMeInvalidEmail 非法 email → 400。
func TestUpdateMeInvalidEmail(t *testing.T) {
	ts := newAuthServerNoLimit(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPatch, ts.TS.URL+"/api/users/me",
		map[string]any{"email": "not-an-email"}, authHeader(token))
	assertEnvelope(t, status, parsed, 400, "")
}

// TestUpdateMeEmailConflict 他人 email → 409 冲突。
func TestUpdateMeEmailConflict(t *testing.T) {
	ts := newAuthServerNoLimit(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	other := &entity.User{
		Guid: uuid.New().String(), Username: "someone", Email: "taken@example.com", Status: 1,
	}
	if err := ts.DB.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPatch, ts.TS.URL+"/api/users/me",
		map[string]any{"email": "taken@example.com"}, authHeader(token))
	assertEnvelope(t, status, parsed, 409, "")
}

// ---- 改密 ----

// TestChangePasswordFlow 旧密码错 401 / 短密码 400 / 成功后旧密码失效。
func TestChangePasswordFlow(t *testing.T) {
	ts := newAuthServerNoLimit(t)
	token := mustLogin(t, ts.TS, "databk", "databk")

	// 旧密码错误 → 401。
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPatch, ts.TS.URL+"/api/users/me/password",
		map[string]any{"current_password": "wrong-old", "new_password": "brand-new-pw"}, authHeader(token))
	assertEnvelope(t, status, parsed, 401, "Current password is incorrect")

	// 新密码过短 → 400。
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPatch, ts.TS.URL+"/api/users/me/password",
		map[string]any{"current_password": "databk", "new_password": "abc"}, authHeader(token))
	assertEnvelope(t, status, parsed, 400, "")

	// 成功 → 200。
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPatch, ts.TS.URL+"/api/users/me/password",
		map[string]any{"current_password": "databk", "new_password": "brand-new-pw"}, authHeader(token))
	if status != 200 || parsed["message"] != "Password changed" {
		t.Fatalf("change password = %d %s", status, raw)
	}

	// 旧密码登录失败；新密码登录成功。
	status, _, _ = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"username": "databk", "password": "databk"}, nil)
	if status != 401 {
		t.Errorf("old password login status = %d, want 401", status)
	}
	status, _, raw = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"username": "databk", "password": "brand-new-pw"}, nil)
	if status != 200 {
		t.Errorf("new password login status = %d: %s", status, raw)
	}
}

// ---- 头像 ----

// TestAvatarLifecycle 上传 → 静态访问 → 删除 → 404；非 webp/超限拒绝。
func TestAvatarLifecycle(t *testing.T) {
	ts := newAuthServerNoLimit(t)
	token := mustLogin(t, ts.TS, "databk", "databk")

	// 非 webp → 400。
	status, parsed := uploadAvatar(t, ts, token, pngPayload())
	assertEnvelope(t, status, parsed, 400, "")

	// 超过 2MB → 400。
	big := append(webpPayload(), make([]byte, 2<<20)...)
	status, parsed = uploadAvatar(t, ts, token, big)
	assertEnvelope(t, status, parsed, 400, "")

	// 合法 webp → 200 {avatar: guid.webp}。
	status, parsed = uploadAvatar(t, ts, token, webpPayload())
	if status != 200 {
		t.Fatalf("upload webp status = %d: %v", status, parsed)
	}
	filename, _ := parsed["avatar"].(string)
	if !strings.HasSuffix(filename, ".webp") || len(filename) != 41 { // uuid(36) + ".webp"(5)
		t.Fatalf("avatar filename = %q", filename)
	}

	// 静态访问：200 + Content-Type: image/webp + Cache-Control。
	resp, err := ts.TS.Client().Get(ts.TS.URL + "/api/avatars/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("avatar GET status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/webp" {
		t.Errorf("Content-Type = %s, want image/webp", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Errorf("Cache-Control = %s", cc)
	}

	// 删除 → 200；随后 404。
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodDelete, ts.TS.URL+"/api/users/me/avatar",
		nil, authHeader(token))
	if status != 200 || parsed["message"] != "Avatar deleted" {
		t.Fatalf("delete avatar = %d %v", status, parsed)
	}
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodGet, ts.TS.URL+"/api/avatars/"+filename, nil, nil)
	assertEnvelope(t, status, parsed, 404, "Avatar not found")
}

// TestAvatarPathTraversal 穿越与非法文件名 → 404。
func TestAvatarPathTraversal(t *testing.T) {
	ts := newAuthServerNoLimit(t)
	for _, name := range []string{"UPPERCASE.webp", "x.png", "a=b.webp", "..dotdot.webp"} {
		status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodGet,
			ts.TS.URL+"/api/avatars/"+name, nil, nil)
		assertEnvelope(t, status, parsed, 404, "Avatar not found")
	}
	// 编码穿越段不匹配 {filename} 白名单 → 404。
	status, _, _ := doJSON(t, ts.TS.Client(), http.MethodGet,
		ts.TS.URL+"/api/avatars/%2e%2e%2fmain.go", nil, nil)
	if status != 404 {
		t.Errorf("encoded traversal status = %d, want 404", status)
	}
}

// TestUserEndpoints401 未认证访问 user 域受保护端点 → 401。
func TestUserEndpoints401(t *testing.T) {
	ts := newAuthServerNoLimit(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPatch, "/api/users/me"},
		{http.MethodPatch, "/api/users/me/password"},
		{http.MethodPost, "/api/users/me/avatar"},
		{http.MethodDelete, "/api/users/me/avatar"},
	} {
		status, parsed, _ := doJSON(t, ts.TS.Client(), tc.method, ts.TS.URL+tc.path, map[string]any{}, nil)
		assertEnvelope(t, status, parsed, 401, "Token expired or revoked")
	}
}
