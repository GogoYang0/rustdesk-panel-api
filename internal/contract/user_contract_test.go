// user_contract_test.go 用户自身端点契约用例：以 openapi.yaml 为准绳，
// 对 T05 全部 user 端点做请求/响应双向校验（M1 退出标准：契约用例全通过）。
// 覆盖端点：PATCH /api/users/me、PATCH /api/users/me/password、
// POST|DELETE /api/users/me/avatar、GET /api/avatars/{filename}。
package contract

import (
	"encoding/json"
	"net/http"
	"testing"
	"uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// contractWebp 构造带 RIFF/WEBP 魔数的最小"图片"（与业务嗅探规则对齐）。
func contractWebp() []byte {
	b := make([]byte, 40)
	copy(b[0:4], "RIFF")
	copy(b[8:12], "WEBP")
	return b
}

// TestContractUpdateMe PATCH /api/users/me 全字段与部分字段更新 → 200 UserPayload。
func TestContractUpdateMe(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)

	// 全字段更新 → 200，payload 回显且含 UserPayload required 字段。
	raw := cs.patch(t, "/api/users/me", map[string]any{
		"display_name": "Contract Admin", "email": "admin@example.com", "note": "keeper",
	}, bearer(token), 200)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("update me body not json: %v (%s)", err, raw)
	}
	for _, key := range []string{"guid", "name", "is_admin"} {
		if _, has := payload[key]; !has {
			t.Errorf("payload.%s missing (required by spec)", key)
		}
	}
	if payload["display_name"] != "Contract Admin" ||
		payload["email"] != "admin@example.com" || payload["note"] != "keeper" {
		t.Errorf("payload = %v", payload)
	}
	if _, has := payload["password"]; has {
		t.Error("payload must not leak password column")
	}

	// 部分字段更新（仅 note）→ 200，其余字段保持。
	raw = cs.patch(t, "/api/users/me", map[string]any{"note": "updated note"}, bearer(token), 200)
	var partial map[string]any
	if err := json.Unmarshal(raw, &partial); err != nil {
		t.Fatal(err)
	}
	if partial["note"] != "updated note" || partial["display_name"] != "Contract Admin" {
		t.Errorf("partial payload = %v", partial)
	}
}

// TestContractUpdateMeInvalidEmail 非法 email（format: email 违规）：
// 契约校验器必须拒绝该请求，服务端防线 400 包络。
func TestContractUpdateMeInvalidEmail(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)
	raw := cs.invalid(t, http.MethodPatch, "/api/users/me",
		map[string]any{"email": "not-an-email"}, bearer(token), 400)
	assertEnvelopeShape(t, raw, 400)
}

// TestContractUpdateMeEmailConflict 他人 email → 409 冲突
// （spec 无显式 409 响应，落 default Error 包络）。
func TestContractUpdateMeEmailConflict(t *testing.T) {
	cs, as := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)
	other := &entity.User{
		Guid: uuid.New().String(), Username: "someone", Email: "taken@example.com", Status: 1,
	}
	if err := as.DB.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	raw := cs.patch(t, "/api/users/me", map[string]any{"email": "taken@example.com"}, bearer(token), 409)
	assertEnvelopeShape(t, raw, 409)
}

// TestContractChangePassword PATCH /api/users/me/password：
// 错旧密码 401 / 短密码 400（minLength 违规）/ 成功 200 MessageResponse。
func TestContractChangePassword(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)

	// 旧密码错误 → 401 包络（请求契约合法：new_password 足够长）。
	raw := cs.patch(t, "/api/users/me/password",
		map[string]any{"current_password": "wrong-old", "new_password": "brand-new-pw"}, bearer(token), 401)
	assertEnvelopeShape(t, raw, 401)

	// 新密码过短 → 400：请求同时违反 spec minLength: 6，走 invalid 断言。
	raw = cs.invalid(t, http.MethodPatch, "/api/users/me/password",
		map[string]any{"current_password": "databk", "new_password": "abc"}, bearer(token), 400)
	assertEnvelopeShape(t, raw, 400)

	// 成功 → 200 {message}。
	raw = cs.patch(t, "/api/users/me/password",
		map[string]any{"current_password": "databk", "new_password": "brand-new-pw"}, bearer(token), 200)
	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp["message"] != "Password changed" {
		t.Errorf("message = %v", resp["message"])
	}
}

// TestContractAvatarLifecycle 头像上传 → 静态访问 → 删除 → 404 全链路契约。
func TestContractAvatarLifecycle(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)

	// 上传 → 200 AvatarResponse {avatar: "<guid>.webp"}。
	raw := cs.postMultipart(t, "/api/users/me/avatar", "avatar", "avatar.webp", contractWebp(), bearer(token), 200)
	var uploaded map[string]any
	if err := json.Unmarshal(raw, &uploaded); err != nil {
		t.Fatalf("upload body not json: %v (%s)", err, raw)
	}
	filename, _ := uploaded["avatar"].(string)
	if len(filename) != 41 || filename[36:] != ".webp" { // uuid(36) + ".webp"(5)
		t.Fatalf("avatar = %q", filename)
	}

	// 静态访问 → 200 image/webp（spec format: binary，原始字节校验）。
	cs.get(t, "/api/avatars/"+filename, nil, 200)

	// 删除 → 200 MessageResponse。
	raw = cs.delete(t, "/api/users/me/avatar", bearer(token), 200)
	var deleted map[string]any
	if err := json.Unmarshal(raw, &deleted); err != nil {
		t.Fatal(err)
	}
	if deleted["message"] != "Avatar deleted" {
		t.Errorf("message = %v", deleted["message"])
	}

	// 静态访问已删头像 → 404 NotFound 包络（文件名格式仍合法）。
	raw = cs.get(t, "/api/avatars/"+filename, nil, 404)
	assertEnvelopeShape(t, raw, 404)
}

// TestContractUploadAvatar400 非 webp 内容：请求契约合法（binary 任意字节），
// 业务嗅探拒绝 → 400 包络。
func TestContractUploadAvatar400(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 'I', 'H', 'D', 'R'}
	raw := cs.postMultipart(t, "/api/users/me/avatar", "avatar", "evil.webp", png, bearer(token), 400)
	assertEnvelopeShape(t, raw, 400)
}

// TestContractAvatarPathPattern 非法文件名（路径参数 pattern 违规）：
// 契约校验器必须拒绝该请求，服务端防线 404。
func TestContractAvatarPathPattern(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	raw := cs.invalid(t, http.MethodGet, "/api/avatars/x.png", nil, nil, 404)
	assertEnvelopeShape(t, raw, 404)
}

// TestContractUserEndpoints401 user 域受保护端点未认证 → 401 包络。
func TestContractUserEndpoints401(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	// 401 断言发生在业务校验前，body 需符合契约形状（required 字段齐全）。
	raw := cs.raw(t, http.MethodPatch, "/api/users/me", map[string]any{}, nil, 401)
	assertEnvelopeShape(t, raw, 401)
	raw = cs.raw(t, http.MethodPatch, "/api/users/me/password",
		map[string]any{"current_password": "x", "new_password": "xxxxxx"}, nil, 401)
	assertEnvelopeShape(t, raw, 401)
	raw = cs.delete(t, "/api/users/me/avatar", nil, 401)
	assertEnvelopeShape(t, raw, 401)
	// multipart 上传端点同样 401。
	raw = cs.postMultipart(t, "/api/users/me/avatar", "avatar", "avatar.webp", contractWebp(), nil, 401)
	assertEnvelopeShape(t, raw, 401)
}
