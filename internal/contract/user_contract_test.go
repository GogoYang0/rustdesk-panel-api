// user_contract_test.go 用户自身端点契约用例：以 openapi.yaml 为准绳，
// 对 M1 全部 me/avatar 端点与 M3 T03 全部管理端用户端点做请求/响应
// 双向校验。覆盖端点：PATCH /api/users/me、PATCH /api/users/me/password、
// POST|DELETE /api/users/me/avatar、GET /api/avatars/{filename}、
// GET|POST /api/users、POST /api/users/invite、
// POST /api/invitations/verify|accept、PATCH /api/users/batch/*（3）、
// GET|PATCH|DELETE /api/users/{guid}、PATCH security、DELETE sessions、
// GET /api/admin/users。
package contract

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"
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

// ---- M3 T03 管理端用户域契约用例 ----
// （assertMessage 复用 device_contract_test.go 既有 helper。）

// assertErrorMessage 断言错误包络形态与 message.error 文案（逐字节）。
func assertErrorMessage(t *testing.T, raw []byte, status int, want string) {
	t.Helper()
	assertEnvelopeShape(t, raw, status)
	var env struct {
		Message map[string]string `json:"message"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("envelope not json: %v (%s)", err, raw)
	}
	if env.Message["error"] != want {
		t.Errorf("message.error = %v, want %q", env.Message, want)
	}
}

// userGuidByUsername 从 GET /api/users 分页结果按 username 取 guid。
func userGuidByUsername(t *testing.T, raw []byte, username string) string {
	t.Helper()
	var page struct {
		Data []struct {
			Guid     string `json:"guid"`
			Username string `json:"username"`
		} `json:"data"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("user page not json: %v (%s)", err, raw)
	}
	for _, u := range page.Data {
		if u.Username == username {
			return u.Guid
		}
	}
	t.Fatalf("user %q not in page (%d rows)", username, page.Total)
	return ""
}

// TestContractUserAdminLifecycle 管理端用户 CRUD/security/force-logout
// 全链契约（POST/GET/GET{guid}/PATCH/PATCH security/DELETE sessions/
// DELETE user）。
func TestContractUserAdminLifecycle(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)

	// 创建 → 200 {"message":"User created successfully"}。
	raw := cs.post(t, "/api/users", map[string]any{
		"username": "contract-u1", "name": "Contract User",
		"password": "secret123", "email": "cu1@example.com",
	}, bearer(token), 200)
	assertMessage(t, raw, "User created successfully")

	// 重名 → 400 {"error":"Username already exists"}。
	raw = cs.post(t, "/api/users", map[string]any{
		"username": "contract-u1", "name": "Dup", "password": "secret123",
		"email": "dup@example.com",
	}, bearer(token), 400)
	assertErrorMessage(t, raw, 400, "Username already exists")

	// 列表 → 200 UserPage（取 guid）。
	raw = cs.get(t, "/api/users", bearer(token), 200)
	guid := userGuidByUsername(t, raw, "contract-u1")

	// 详情 → 200 UserView：name=显示名（契约 name 语义）。
	raw = cs.get(t, "/api/users/"+guid, bearer(token), 200)
	var view map[string]any
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("user view not json: %v (%s)", err, raw)
	}
	if view["name"] != "Contract User" || view["username"] != "contract-u1" ||
		view["status"] != float64(1) {
		t.Errorf("view = %v", view)
	}
	if _, has := view["is_protected"]; !has {
		t.Error("view.is_protected missing (required by spec)")
	}

	// PATCH name → 200 "User updated"。
	raw = cs.patch(t, "/api/users/"+guid, map[string]any{"name": "Renamed"}, bearer(token), 200)
	assertMessage(t, raw, "User updated")

	// 全空 body → 400 "No fields to update"。
	raw = cs.patch(t, "/api/users/"+guid, map[string]any{}, bearer(token), 400)
	assertErrorMessage(t, raw, 400, "No fields to update")

	// is_admin 未知字段 → 400（绑定层 DisallowUnknownFields；spec 未禁
	// additionalProperties，请求契约放行、服务端拒绝）。
	raw = cs.patch(t, "/api/users/"+guid, map[string]any{"is_admin": true}, bearer(token), 400)
	assertEnvelopeShape(t, raw, 400)

	// status → 200（同事务撤 token）。
	cs.patch(t, "/api/users/"+guid, map[string]any{"status": 0}, bearer(token), 200)

	// security：短口令（spec minLength:6 违规）→ 400；合规 → 200。
	raw = cs.invalid(t, http.MethodPatch, "/api/users/"+guid+"/security",
		map[string]any{"new_password": "abc"}, bearer(token), 400)
	assertEnvelopeShape(t, raw, 400)
	raw = cs.patch(t, "/api/users/"+guid+"/security",
		map[string]any{"tfa_enforce": true, "new_password": "brand-new-pw"}, bearer(token), 200)
	assertMessage(t, raw, "Security settings updated")

	// force logout → 200 "Sessions deleted"。
	raw = cs.delete(t, "/api/users/"+guid+"/sessions", bearer(token), 200)
	assertMessage(t, raw, "Sessions deleted")

	// 删除 → 200 "User deleted"；详情 → 404。
	raw = cs.delete(t, "/api/users/"+guid, bearer(token), 200)
	assertMessage(t, raw, "User deleted")
	raw = cs.get(t, "/api/users/"+guid, bearer(token), 404)
	assertEnvelopeShape(t, raw, 404)
}

// TestContractUserOwnerProtection 所有者账号不可禁用/删除（403 固定文案）。
func TestContractUserOwnerProtection(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)
	guid, _ := login["user"].(map[string]any)["guid"].(string)
	if guid == "" {
		t.Fatal("owner guid missing")
	}

	raw := cs.patch(t, "/api/users/"+guid, map[string]any{"status": 0}, bearer(token), 403)
	assertEnvelopeShape(t, raw, 403)
	var env struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &env)
	if env.Message != "The system owner account cannot be disabled or deleted" {
		t.Errorf("message = %q", env.Message)
	}
	raw = cs.delete(t, "/api/users/"+guid, bearer(token), 403)
	assertEnvelopeShape(t, raw, 403)
}

// TestContractUserInviteFlow 邀请三端点全链：invite（邮件禁用 → token
// 明文降级）→ verify → accept（激活后可登录）→ 已用/无效 400。
func TestContractUserInviteFlow(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)

	// invite → 200 InviteResult：message 恒有；SMTP 禁用 → token 降级。
	raw := cs.post(t, "/api/users/invite", map[string]any{
		"email": "invite@example.com", "name": "Invitee",
	}, bearer(token), 200)
	var inv map[string]any
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatalf("invite body not json: %v (%s)", err, raw)
	}
	if inv["message"] != "Invitation sent" {
		t.Errorf("message = %v", inv["message"])
	}
	invToken, _ := inv["token"].(string)
	if len(invToken) != 64 { // 32B hex
		t.Fatalf("degraded token = %q", invToken)
	}

	// verify → 200 InvitationInfo（display_name 可空串）。
	raw = cs.post(t, "/api/invitations/verify", map[string]any{"token": invToken}, nil, 200)
	var info map[string]any
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("verify body not json: %v (%s)", err, raw)
	}
	if info["name"] != "Invitee" || info["email"] != "invite@example.com" {
		t.Errorf("info = %v", info)
	}
	if dn, has := info["display_name"]; !has || dn != "" {
		t.Errorf("display_name = %v (want empty string)", dn)
	}

	// accept 短口令（spec minLength:6 违规）→ 400。
	raw = cs.invalid(t, http.MethodPost, "/api/invitations/accept",
		map[string]any{"token": invToken, "password": "abc"}, nil, 400)
	assertEnvelopeShape(t, raw, 400)

	// accept → 200 "Account activated, please log in"。
	raw = cs.post(t, "/api/invitations/accept",
		map[string]any{"token": invToken, "password": "secret123"}, nil, 200)
	assertMessage(t, raw, "Account activated, please log in")

	// 已用 → 400 固定文案。
	raw = cs.post(t, "/api/invitations/verify", map[string]any{"token": invToken}, nil, 400)
	assertErrorMessage(t, raw, 400, "Invitation has already been used")

	// 无效 token → 400 固定文案。
	raw = cs.post(t, "/api/invitations/verify",
		map[string]any{"token": strings.Repeat("f", 64)}, nil, 400)
	assertErrorMessage(t, raw, 400, "Invalid invitation token")

	// 激活后可登录（贯通 M1 登录流）。
	cs.post(t, "/api/login", map[string]any{
		"type": "account", "username": "invite@example.com", "password": "secret123",
		"id": "dev-2", "uuid": "uuid-2",
		"deviceInfo": map[string]any{"name": "contract-web", "os": "linux", "type": "web"},
	}, nil, 200)
}

// TestContractUserBatch 批量三端点：部分成功（owner 进 failed[]）/
// 缺失目标 404 / minItems 违规 / security / sessions。
func TestContractUserBatch(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)
	ownerGuid, _ := login["user"].(map[string]any)["guid"].(string)

	mk := func(name string) string {
		cs.post(t, "/api/users", map[string]any{
			"username": name, "name": name, "password": "secret123",
			"email": name + "@example.com",
		}, bearer(token), 200)
		raw := cs.get(t, "/api/users", bearer(token), 200)
		return userGuidByUsername(t, raw, name)
	}
	u1 := mk("batch-u1")
	u2 := mk("batch-u2")

	// 批量停用 → 200 BatchResult 双成功。
	raw := cs.patch(t, "/api/users/batch/status",
		map[string]any{"guids": []string{u1, u2}, "status": 0}, bearer(token), 200)
	var br struct {
		Succeeded      []string         `json:"succeeded"`
		Failed         []map[string]any `json:"failed"`
		Total          int              `json:"total"`
		SucceededCount int              `json:"succeededCount"`
		FailedCount    int              `json:"failedCount"`
	}
	if err := json.Unmarshal(raw, &br); err != nil {
		t.Fatalf("batch body not json: %v (%s)", err, raw)
	}
	if br.SucceededCount != 2 || br.Total != 2 || len(br.Succeeded) != 2 || len(br.Failed) != 0 {
		t.Errorf("batch result = %+v", br)
	}

	// 目标含不存在用户 → 404 整批（AssertUsersMutation）。
	raw = cs.patch(t, "/api/users/batch/status",
		map[string]any{"guids": []string{u1, "00000000-0000-4000-8000-000000000000"}, "status": 1},
		bearer(token), 404)
	assertEnvelopeShape(t, raw, 404)

	// owner 不可禁用 → 部分成功（owner 进 failed[]，其余成功）。
	raw = cs.patch(t, "/api/users/batch/status",
		map[string]any{"guids": []string{ownerGuid, u1}, "status": 0}, bearer(token), 200)
	if err := json.Unmarshal(raw, &br); err != nil {
		t.Fatal(err)
	}
	if br.SucceededCount != 1 || br.FailedCount != 1 || len(br.Succeeded) != 1 || br.Succeeded[0] != u1 {
		t.Errorf("partial batch result = %+v", br)
	}
	if len(br.Failed) != 1 || br.Failed[0]["guid"] != ownerGuid ||
		br.Failed[0]["reason"] != "The system owner account cannot be disabled or deleted" {
		t.Errorf("partial batch failed = %+v", br.Failed)
	}

	// 空数组 → spec minItems 违规：校验器拒绝 + 服务端 400。
	raw = cs.invalid(t, http.MethodPatch, "/api/users/batch/status",
		map[string]any{"guids": []string{}, "status": 1}, bearer(token), 400)
	assertEnvelopeShape(t, raw, 400)

	// 批量 security → 200；短口令（spec minLength:6 违规）→ 400。
	raw = cs.patch(t, "/api/users/batch/security",
		map[string]any{"guids": []string{u1}, "tfa_enforce": true}, bearer(token), 200)
	assertMessage(t, raw, "Bulk security settings updated")
	raw = cs.invalid(t, http.MethodPatch, "/api/users/batch/security",
		map[string]any{"guids": []string{u1}, "new_password": "abc"}, bearer(token), 400)
	assertEnvelopeShape(t, raw, 400)

	// 批量 force logout（DELETE 携 body）→ 200。
	raw = cs.raw(t, http.MethodDelete, "/api/users/batch/sessions",
		map[string]any{"guids": []string{u1}}, bearer(token), 200)
	assertMessage(t, raw, "Forced logout successful")
}

// TestContractBatchStatusDrift409 操作者快照与库内状态并发漂移 →
// 409 整批拒绝。注入方式：one-shot GORM Query 回调（gorm:query 之前）
// 识别 BatchStatus 事务内的全列单行重读（Dest 为 *entity.User 且无
// 显式 Select——其余用户查询均走 publicSelect 显式列清单）并在执行前
// 篡改目标行 status，使快照比对未命中。
func TestContractBatchStatusDrift409(t *testing.T) {
	cs, as := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)

	cs.post(t, "/api/users", map[string]any{
		"username": "drift-u1", "name": "Drift", "password": "secret123",
		"email": "drift-u1@example.com",
	}, bearer(token), 200)
	raw := cs.get(t, "/api/users", bearer(token), 200)
	guid := userGuidByUsername(t, raw, "drift-u1")

	var fired atomic.Bool
	if err := as.DB.Callback().Query().Before("gorm:query").
		Register("contract:drift_inject", func(tx *gorm.DB) {
			if !fired.CompareAndSwap(false, true) {
				return
			}
			// 仅命中事务内全列单行重读（First(&entity.User{}) 无
			// 显式 Select）；publicSelect 链携带列清单即排除。
			if _, ok := tx.Statement.Dest.(*entity.User); !ok || len(tx.Statement.Selects) > 0 {
				fired.Store(false) // 未命中目标查询，保持 armed
				return
			}
			_ = tx.Exec("UPDATE users SET status = 9 WHERE guid = ?", guid).Error
		}); err != nil {
		t.Fatal(err)
	}

	raw = cs.patch(t, "/api/users/batch/status",
		map[string]any{"guids": []string{guid}, "status": 0}, bearer(token), 409)
	assertEnvelopeShape(t, raw, 409)
	var env struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &env)
	if env.Message != "User info has changed, please try again" {
		t.Errorf("message = %q", env.Message)
	}
}

// TestContractUserAdminList GET /api/admin/users：过滤分页 +
// role_names（admin 追加 'Super Admin'）+ is_protected。
func TestContractUserAdminList(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)

	raw := cs.get(t, "/api/admin/users?current=1&pageSize=10&name=databk&is_admin=1", bearer(token), 200)
	var page struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("admin page not json: %v (%s)", err, raw)
	}
	if page.Total < 1 || len(page.Data) < 1 {
		t.Fatalf("admin page = %+v", page)
	}
	row := page.Data[0]
	for _, key := range []string{"guid", "name", "username", "status", "is_admin", "is_protected", "role_names"} {
		if _, has := row[key]; !has {
			t.Errorf("admin row.%s missing (required by spec)", key)
		}
	}
	if row["name"] != "databk" || row["is_protected"] != true {
		t.Errorf("admin row = %v", row)
	}
	found := false
	if names, ok := row["role_names"].([]any); ok {
		for _, n := range names {
			if n == "Super Admin" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("role_names missing 'Super Admin': %v", row["role_names"])
	}

	// pageSize=1 → 单行。
	raw = cs.get(t, "/api/admin/users?pageSize=1", bearer(token), 200)
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Data) != 1 {
		t.Errorf("pageSize=1 rows = %d", len(page.Data))
	}
}

// TestContractUserM3Endpoints401 M3 用户域受保护端点未认证 → 401。
func TestContractUserM3Endpoints401(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	raw := cs.get(t, "/api/users", nil, 401)
	assertEnvelopeShape(t, raw, 401)
	raw = cs.get(t, "/api/admin/users", nil, 401)
	assertEnvelopeShape(t, raw, 401)
	raw = cs.post(t, "/api/users", map[string]any{
		"username": "ghost", "name": "ghost", "password": "xxxxxx", "email": "ghost@example.com",
	}, nil, 401)
	assertEnvelopeShape(t, raw, 401)
	raw = cs.patch(t, "/api/users/batch/status",
		map[string]any{"guids": []string{"00000000-0000-4000-8000-000000000000"}, "status": 1}, nil, 401)
	assertEnvelopeShape(t, raw, 401)
}
