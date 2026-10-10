// 外部测试包：testutil 组装完整路由依赖 internal/server，
// 内部测试包会构成 import cycle，故用 server_test 挂载。
package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// ---- 通用辅助 ----

// doJSON 发送 JSON 请求；返回状态码、（对象形态时的）解析 map 与原始字节。
// 数组响应不解析 map（由用例直接解析 raw），解析失败即 Fatal。
func doJSON(t *testing.T, client *http.Client, method, rawURL string, body any, headers map[string]string) (int, map[string]any, []byte) {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	parsed := map[string]any{}
	ct := resp.Header.Get("Content-Type")
	if len(raw) > 0 && strings.Contains(ct, "json") {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			// 顶层数组（sessions/passkey list/login-options）合法，交给用例解析 raw。
			var arr []any
			if err2 := json.Unmarshal(raw, &arr); err2 != nil {
				t.Fatalf("decode json %s: %v (%s)", rawURL, err, raw)
			}
		}
	}
	return resp.StatusCode, parsed, raw
}

// authHeader Bearer 头。
func authHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// loginAs 执行标准登录（含设备信息）。
func loginAs(t *testing.T, ts *httptest.Server, username, password string) (int, map[string]any) {
	t.Helper()
	status, parsed, _ := doJSON(t, ts.Client(), http.MethodPost, ts.URL+"/api/login", map[string]any{
		"username": username,
		"password": password,
		"id":       "dev-1",
		"uuid":     "uuid-1",
		"deviceInfo": map[string]any{
			"name": "test-web", "os": "linux", "type": "web",
		},
	}, nil)
	return status, parsed
}

// mustLogin 登录失败即 Fatal，返回 access_token。
func mustLogin(t *testing.T, ts *httptest.Server, username, password string) string {
	t.Helper()
	status, parsed := loginAs(t, ts, username, password)
	if status != 200 {
		t.Fatalf("login %s status = %d: %s", username, status, parsed["message"])
	}
	token, _ := parsed["access_token"].(string)
	if token == "" {
		t.Fatalf("login %s: missing access_token", username)
	}
	return token
}

// newAuthServer 独立全栈服务器（每测试隔离限流桶）。
func newAuthServer(t *testing.T) *apptest.AppServer {
	t.Helper()
	return apptest.NewAppServer(t, nil)
}

// newAuthServerNoLimit 禁用限流的全栈服务器（多步登录用例会超过
// login 5/min 配额；限流行为由 TestLoginRateLimit 专项覆盖）。
func newAuthServerNoLimit(t *testing.T) *apptest.AppServer {
	t.Helper()
	return apptest.NewAppServer(t, func(c *config.Config) { c.RateLimitEnabled = false })
}

// assertEnvelope 断言错误包络形状与文案（共享知识 1）。
func assertEnvelope(t *testing.T, status int, parsed map[string]any, wantStatus int, wantMessage string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status = %d, want %d (body %v)", status, wantStatus, parsed)
	}
	if got, _ := parsed["statusCode"].(float64); int(got) != wantStatus {
		t.Errorf("statusCode = %v, want %d", parsed["statusCode"], wantStatus)
	}
	if got, _ := parsed["error"].(string); got == "" {
		t.Errorf("error field empty: %v", parsed)
	}
	if wantMessage != "" {
		if got, _ := parsed["message"].(string); got != wantMessage {
			t.Errorf("message = %v, want %q", parsed["message"], wantMessage)
		}
	}
}

// findUserGuid 查询用户 guid。
func findUserGuid(t *testing.T, ts *apptest.AppServer, username string) string {
	t.Helper()
	var u entity.User
	if err := ts.DB.Where("username = ?", username).First(&u).Error; err != nil {
		t.Fatalf("find user %s: %v", username, err)
	}
	return u.Guid
}

// ---- 场景 A：普通账号密码登录 ----

// TestLoginAccountSuccess 普通登录成功与 user payload 契约字段。
func TestLoginAccountSuccess(t *testing.T) {
	ts := newAuthServer(t)
	status, parsed := loginAs(t, ts.TS, "databk", "databk")
	if status != 200 {
		t.Fatalf("login status = %d: %v", status, parsed)
	}
	if got, _ := parsed["type"].(string); got != "account" {
		t.Errorf("type = %v, want account", parsed["type"])
	}
	token, _ := parsed["access_token"].(string)
	if token == "" {
		t.Fatal("access_token missing")
	}
	user, ok := parsed["user"].(map[string]any)
	if !ok {
		t.Fatalf("user missing: %v", parsed)
	}
	if user["name"] != "databk" {
		t.Errorf("user.name = %v", user["name"])
	}
	if user["is_admin"] != true {
		t.Errorf("user.is_admin = %v, want true（snake_case 契约）", user["is_admin"])
	}
	if user["has_password"] != true {
		t.Errorf("user.has_password = %v", user["has_password"])
	}
	if user["tfa_enabled"] != false {
		t.Errorf("user.tfa_enabled = %v", user["tfa_enabled"])
	}
}

// TestLoginBadPassword 错误密码 → 401 纯文本 message。
func TestLoginBadPassword(t *testing.T) {
	ts := newAuthServer(t)
	status, parsed := loginAs(t, ts.TS, "databk", "wrong-password")
	assertEnvelope(t, status, parsed, 401, "Username or password is incorrect")
}

// TestLoginDisabledUser 禁用用户 → 401 User is disabled。
func TestLoginDisabledUser(t *testing.T) {
	ts := newAuthServer(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("pw123456"), 10)
	if err != nil {
		t.Fatal(err)
	}
	disabled := &entity.User{
		Guid: uuid.New().String(), Username: "disabled1", Email: "disabled1@example.com",
		Password: string(hash), Status: 0,
	}
	if err := ts.DB.Create(disabled).Error; err != nil {
		t.Fatal(err)
	}
	status, parsed := loginAs(t, ts.TS, "disabled1", "pw123456")
	assertEnvelope(t, status, parsed, 401, "User is disabled")
}

// TestLoginMissingFields 缺参 → 400 对象形态 message。
func TestLoginMissingFields(t *testing.T) {
	ts := newAuthServer(t)
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"username": "only-user"}, nil)
	if status != 400 {
		t.Fatalf("status = %d: %s", status, raw)
	}
	msg, ok := parsed["message"].(map[string]any)
	if !ok {
		t.Fatalf("message should be object form, got: %v", parsed["message"])
	}
	if msg["error"] != "Username and password are required" {
		t.Errorf("message.error = %v", msg["error"])
	}
}

// TestLoginSmsCodeUnavailable sms_code → 400 未开放。
func TestLoginSmsCodeUnavailable(t *testing.T) {
	ts := newAuthServer(t)
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"type": "sms_code", "username": "databk", "password": "databk"}, nil)
	if status != 400 {
		t.Fatalf("status = %d: %s", status, raw)
	}
	msg, _ := parsed["message"].(map[string]any)
	if msg["error"] != "SMS login is not available" {
		t.Errorf("message.error = %v", msg["error"])
	}
}

// ---- 场景 D：受保护端点会话校验 ----

// TestSessionsLifecycle 会话列表/撤销/立即 401。
func TestSessionsLifecycle(t *testing.T) {
	ts := newAuthServer(t)
	token1 := mustLogin(t, ts.TS, "databk", "databk")
	token2 := mustLogin(t, ts.TS, "databk", "databk")

	status, _, raw := doJSON(t, ts.TS.Client(), http.MethodGet, ts.TS.URL+"/api/sessions", nil, authHeader(token1))
	if status != 200 {
		t.Fatalf("sessions status = %d: %s", status, raw)
	}
	var sessions []map[string]any
	if err := json.Unmarshal(raw, &sessions); err != nil {
		t.Fatalf("sessions should be array: %s", raw)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions len = %d, want 2", len(sessions))
	}
	first, _ := sessions[0]["jti"].(string)
	if first == "" {
		t.Fatal("session jti missing")
	}
	if sessions[0]["deviceName"] != "test-web" {
		t.Errorf("deviceName = %v, want test-web", sessions[0]["deviceName"])
	}

	// 撤销列表首项（即 token2 对应的最新会话）→ 200 MessageResponse
	// （成功响应不带错误包络，包络仅用于失败，共享知识 1）。
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodDelete,
		ts.TS.URL+"/api/sessions/"+first, nil, authHeader(token1))
	if status != 200 || parsed["message"] != "Session revoked" {
		t.Fatalf("revoke = %d %s", status, raw)
	}

	// 被撤销的 token2 下一次请求立即 401（设计场景 D）。
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPost,
		ts.TS.URL+"/api/currentUser", nil, authHeader(token2))
	assertEnvelope(t, status, parsed, 401, "Token expired or revoked")

	// 发起撤销的 token1 不受影响。
	status, _, raw = doJSON(t, ts.TS.Client(), http.MethodPost,
		ts.TS.URL+"/api/currentUser", nil, authHeader(token1))
	if status != 200 {
		t.Fatalf("other session should survive: %d %s", status, raw)
	}
}

// TestRevokeOtherSession404 撤销不存在会话 → 404。
func TestRevokeOtherSession404(t *testing.T) {
	ts := newAuthServer(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodDelete,
		ts.TS.URL+"/api/sessions/00000000-0000-4000-8000-000000000000", nil, authHeader(token))
	assertEnvelope(t, status, parsed, 404, "Session not found")
}

// TestLogoutRevokesToken 登出后 token 失效 + 设备维度撤销。
func TestLogoutRevokesToken(t *testing.T) {
	ts := newAuthServer(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	status, _, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/logout",
		map[string]any{"id": "dev-1", "uuid": "uuid-1"}, authHeader(token))
	if status != 200 {
		t.Fatalf("logout status = %d: %s", status, raw)
	}
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/currentUser", nil, authHeader(token))
	assertEnvelope(t, status, parsed, 401, "Token expired or revoked")
}

// TestCurrentUserPayload currentUser 返回 snake_case payload 且不泄敏感列。
func TestCurrentUserPayload(t *testing.T) {
	ts := newAuthServer(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	status, _, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/currentUser", nil, authHeader(token))
	if status != 200 {
		t.Fatalf("currentUser status = %d: %s", status, raw)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["name"] != "databk" || payload["is_admin"] != true {
		t.Errorf("payload = %v", payload)
	}
	if _, has := payload["password"]; has {
		t.Error("payload must not leak password column")
	}
}

// TestNoToken401 未带 token → 401 固定文案。
func TestNoToken401(t *testing.T) {
	ts := newAuthServer(t)
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/currentUser", nil, nil)
	assertEnvelope(t, status, parsed, 401, "Token expired or revoked")
}

// TestTamperedToken401 伪造签名 token → 401。
func TestTamperedToken401(t *testing.T) {
	ts := newAuthServer(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	tampered := token[:len(token)-2] + "xx"
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/currentUser", nil, authHeader(tampered))
	assertEnvelope(t, status, parsed, 401, "Token expired or revoked")
}

// ---- TOTP 2FA ----

// TestTfaFullFlow 绑定 → 两步登录 → 复用拒绝 → 关闭。
func TestTfaFullFlow(t *testing.T) {
	ts := newAuthServerNoLimit(t)
	token := mustLogin(t, ts.TS, "databk", "databk")

	// setup：{secret, otpauth_url}，issuer 固定 RustDesk。
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/2fa/setup", nil, authHeader(token))
	if status != 200 {
		t.Fatalf("setup status = %d: %s", status, raw)
	}
	secret, _ := parsed["secret"].(string)
	otpauthURL, _ := parsed["otpauth_url"].(string)
	if secret == "" || !strings.HasPrefix(otpauthURL, "otpauth://totp/") {
		t.Fatalf("setup response invalid: %v", parsed)
	}
	if !strings.Contains(otpauthURL, "issuer=RustDesk") {
		t.Errorf("otpauth_url missing issuer=RustDesk: %s", otpauthURL)
	}

	// verify：偏离 ±1 窗口外的码 → 401。
	staleCode, err := totp.GenerateCode(secret, time.Now().Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/2fa/verify",
		map[string]any{"tfaCode": staleCode}, authHeader(token))
	assertEnvelope(t, status, parsed, 401, "Invalid verification code")

	// verify 正确码 → 200 绑定。
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, _, raw = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/2fa/verify",
		map[string]any{"tfaCode": code}, authHeader(token))
	if status != 200 {
		t.Fatalf("verify status = %d: %s", status, raw)
	}

	// 两步登录第一步：type=email_check + tfa_type=tfa_check + secret（共享知识 7）。
	status, parsed = loginAs(t, ts.TS, "databk", "databk")
	if status != 200 {
		t.Fatalf("two-step step1 status = %d: %v", status, parsed)
	}
	if got, _ := parsed["type"].(string); got != "email_check" {
		t.Errorf("type = %v, want email_check（客户端兼容形态，不得纠正）", parsed["type"])
	}
	if got, _ := parsed["tfa_type"].(string); got != "tfa_check" {
		t.Errorf("tfa_type = %v, want tfa_check", parsed["tfa_type"])
	}
	stepSecret, _ := parsed["secret"].(string)
	if stepSecret == "" {
		t.Fatal("step1 secret missing")
	}
	if _, hasToken := parsed["access_token"]; hasToken {
		t.Error("step1 must not issue access_token")
	}

	// 第二步错误码 → 401。
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"type": "tfa_code", "secret": stepSecret, "tfaCode": "999999"}, nil)
	assertEnvelope(t, status, parsed, 401, "Invalid verification code")

	// 第二步正确码 → 200 access_token。
	code3, _ := totp.GenerateCode(secret, time.Now())
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"type": "tfa_code", "secret": stepSecret, "tfaCode": code3}, nil)
	if status != 200 {
		t.Fatalf("two-step step2 status = %d: %v", status, parsed)
	}
	finalToken, _ := parsed["access_token"].(string)
	if finalToken == "" {
		t.Fatal("step2 access_token missing")
	}

	// secret 复用（used=1）→ 401 会话无效。
	code4, _ := totp.GenerateCode(secret, time.Now())
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"type": "tfa_code", "secret": stepSecret, "tfaCode": code4}, nil)
	assertEnvelope(t, status, parsed, 401, "Invalid or expired verification session")

	// 关闭 2FA：需当前验证码。
	code5, _ := totp.GenerateCode(secret, time.Now())
	status, _, raw = doJSON(t, ts.TS.Client(), http.MethodDelete, ts.TS.URL+"/api/2fa",
		map[string]any{"tfaCode": code5}, authHeader(finalToken))
	if status != 200 {
		t.Fatalf("disable status = %d: %s", status, raw)
	}
	status, parsed = loginAs(t, ts.TS, "databk", "databk")
	if got, _ := parsed["type"].(string); got != "account" {
		t.Errorf("after disable, type = %v, want account (login status=%d)", parsed["type"], status)
	}
}

// TestTfaFakeSecret 伪造两步 secret → 401。
func TestTfaFakeSecret(t *testing.T) {
	ts := newAuthServer(t)
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"type": "tfa_code", "secret": "not-a-secret", "tfaCode": "123456"}, nil)
	assertEnvelope(t, status, parsed, 401, "Invalid or expired verification session")
}

// ---- Passkey（WebAuthn） ----

// registerPasskey 为用户注册一把软件 passkey（复用流程）。
func registerPasskey(t *testing.T, ts *apptest.AppServer, token, userGuid string) *testutil.SoftAuthenticator {
	t.Helper()
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost,
		ts.TS.URL+"/api/passkey/register/begin", nil, authHeader(token))
	if status != 200 {
		t.Fatalf("register begin: %d %s", status, raw)
	}
	options, ok := parsed["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("register begin missing publicKey: %v", parsed)
	}
	authr, err := testutil.NewSoftAuthenticator(ts.Config.WebAuthnRPID, ts.Config.WebAuthnOrigins[0], []byte(userGuid))
	if err != nil {
		t.Fatal(err)
	}
	regResp, err := authr.CreateRegistrationResponse(options["challenge"].(string))
	if err != nil {
		t.Fatal(err)
	}
	status, _, raw = doJSON(t, ts.TS.Client(), http.MethodPost,
		ts.TS.URL+"/api/passkey/register/verify", map[string]any{"response": regResp, "name": "test-key"},
		authHeader(token))
	if status != 200 {
		t.Fatalf("register verify: %d %s", status, raw)
	}
	return authr
}

// TestPasskeyRegisterAndLogin 注册 + 免密登录 + counter 回退拒绝。
func TestPasskeyRegisterAndLogin(t *testing.T) {
	ts := newAuthServer(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	userGuid := findUserGuid(t, ts, "databk")
	authr := registerPasskey(t, ts, token, userGuid)

	// 列表。
	_, _, raw := doJSON(t, ts.TS.Client(), http.MethodGet, ts.TS.URL+"/api/passkey/list", nil, authHeader(token))
	var views []map[string]any
	if err := json.Unmarshal(raw, &views); err != nil || len(views) != 1 {
		t.Fatalf("passkey list = %s (err %v)", raw, err)
	}
	if views[0]["name"] != "test-key" {
		t.Errorf("passkey name = %v", views[0]["name"])
	}

	// 免密登录第一步：{secret, options.publicKey.challenge}。
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/passkey/auth/begin", nil, nil)
	if status != 200 {
		t.Fatalf("auth begin status = %d: %s", status, raw)
	}
	secret, _ := parsed["secret"].(string)
	options, _ := parsed["options"].(map[string]any)
	publicKey, _ := options["publicKey"].(map[string]any)
	if secret == "" || publicKey == nil {
		t.Fatalf("auth begin invalid: %v", parsed)
	}

	// 免密登录第二步 → 200 access_token。
	assertResp, err := authr.CreateAssertionResponse(publicKey["challenge"].(string))
	if err != nil {
		t.Fatal(err)
	}
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/passkey/auth/verify",
		map[string]any{"secret": secret, "response": assertResp, "id": "dev-1", "uuid": "uuid-1",
			"deviceInfo": map[string]any{"name": "test-web", "os": "linux", "type": "web"}}, nil)
	if status != 200 {
		t.Fatalf("auth verify status = %d: %v", status, parsed)
	}
	if _, ok := parsed["access_token"].(string); !ok {
		t.Fatalf("passkey login missing access_token: %v", parsed)
	}

	// counter 回退（克隆模拟：回放旧计数器）→ 401 拒绝。
	status, parsed, raw = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/passkey/auth/begin", nil, nil)
	if status != 200 {
		t.Fatalf("auth begin #2 status = %d: %s", status, raw)
	}
	secret2, _ := parsed["secret"].(string)
	options2, _ := parsed["options"].(map[string]any)
	publicKey2, _ := options2["publicKey"].(map[string]any)
	replay, err := authr.CreateAssertionResponseWithCounter(publicKey2["challenge"].(string), 2)
	if err != nil {
		t.Fatal(err)
	}
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/passkey/auth/verify",
		map[string]any{"secret": secret2, "response": replay}, nil)
	assertEnvelope(t, status, parsed, 401, "Passkey verification failed")
}

// TestPasskeyTfaFlow passkey 作为二次验证的两步登录（passkey_check 形态）。
func TestPasskeyTfaFlow(t *testing.T) {
	ts := newAuthServer(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	userGuid := findUserGuid(t, ts, "databk")
	authr := registerPasskey(t, ts, token, userGuid)

	// 开启 passkey 2FA。
	status, _, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/passkey/tfa",
		map[string]any{"enabled": true}, authHeader(token))
	if status != 200 {
		t.Fatalf("tfa toggle: %d %s", status, raw)
	}

	// 登录第一步：tfa_type=passkey_check + passkey_options + secret。
	status, parsed := loginAs(t, ts.TS, "databk", "databk")
	if status != 200 {
		t.Fatalf("step1: %d %v", status, parsed)
	}
	if got, _ := parsed["tfa_type"].(string); got != "passkey_check" {
		t.Fatalf("tfa_type = %v, want passkey_check", parsed["tfa_type"])
	}
	passkeyOptions, _ := parsed["passkey_options"].(map[string]any)
	stepSecret, _ := parsed["secret"].(string)
	if passkeyOptions == nil || stepSecret == "" {
		t.Fatalf("step1 missing passkey_options/secret: %v", parsed)
	}
	publicKey, _ := passkeyOptions["publicKey"].(map[string]any)

	// 第二步：passkey_tfa 会话断言 → 200 access_token。
	assertResp, err := authr.CreateAssertionResponse(publicKey["challenge"].(string))
	if err != nil {
		t.Fatal(err)
	}
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/passkey/auth/verify",
		map[string]any{"secret": stepSecret, "response": assertResp}, nil)
	if status != 200 {
		t.Fatalf("passkey_tfa step2: %d %v", status, parsed)
	}
	if _, ok := parsed["access_token"].(string); !ok {
		t.Fatalf("passkey_tfa missing token: %v", parsed)
	}
}

// TestPasskeyDeleteOtherUser 删除不存在的凭据 → 404（不泄漏存在性）。
func TestPasskeyDeleteOtherUser(t *testing.T) {
	ts := newAuthServer(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodDelete,
		ts.TS.URL+"/api/passkey/00000000-0000-4000-8000-000000000000", nil, authHeader(token))
	assertEnvelope(t, status, parsed, 404, "Passkey not found")
}

// ---- OIDC 授权流 ----

// fakeProvider httptest 假 OIDC 提供商（authorize/token/userinfo，强制 PKCE）。
type fakeProvider struct {
	TS        *httptest.Server
	mu        sync.Mutex
	challenge map[string]string // code → S256 challenge
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	fp := &fakeProvider{challenge: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "authcode-" + uuid.New().String()[:8]
		fp.mu.Lock()
		fp.challenge[code] = q.Get("code_challenge")
		fp.mu.Unlock()
		target := q.Get("redirect_uri") + "?code=" + url.QueryEscape(code) +
			"&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, target, http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		code := r.PostForm.Get("code")
		verifier := r.PostForm.Get("code_verifier")
		fp.mu.Lock()
		want, ok := fp.challenge[code]
		fp.mu.Unlock()
		if !ok {
			http.Error(w, "unknown code", 400)
			return
		}
		sum := sha256.Sum256([]byte(verifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != want {
			http.Error(w, "pkce mismatch", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fp-access-token","token_type":"bearer"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer fp-access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"sub-42","preferred_username":"oidcuser","name":"OIDC User","email":"oidcuser@example.com"}`))
	})
	fp.TS = httptest.NewServer(mux)
	t.Cleanup(fp.TS.Close)
	return fp
}

// seedProvider 注入启用中的假 OIDC 提供商。
func seedProvider(t *testing.T, ts *apptest.AppServer, fp *fakeProvider) {
	t.Helper()
	p := &entity.OidcProvider{
		Guid: uuid.New().String(), Name: "acme", Type: "oidc",
		Issuer: fp.TS.URL, ClientId: "panel-client", ClientSecret: "panel-secret",
		Scope:                 "openid profile email",
		AuthorizationEndpoint: fp.TS.URL + "/authorize",
		TokenEndpoint:         fp.TS.URL + "/token",
		UserinfoEndpoint:      fp.TS.URL + "/userinfo",
		Enabled:               true, Priority: 1,
	}
	if err := ts.DB.Create(p).Error; err != nil {
		t.Fatal(err)
	}
}

// runOidcFlow 走完整授权流（发起 → 跳转 → 回调），返回轮询 code。
func runOidcFlow(t *testing.T, ts *apptest.AppServer, extra map[string]any) string {
	t.Helper()
	body := map[string]any{"provider": "acme"}
	for k, v := range extra {
		body[k] = v
	}
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/oidc/auth", body, nil)
	if status != 200 {
		t.Fatalf("oidc auth status = %d: %s", status, raw)
	}
	authURL, _ := parsed["url"].(string)
	if authURL == "" {
		t.Fatalf("oidc auth missing url: %v", parsed)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	pollCode := u.Query().Get("login_code")
	if pollCode == "" {
		t.Fatalf("authorization url missing login_code: %s", authURL)
	}
	// 浏览器跳转假 provider → 302 回本服务回调 → 渲染 HTML。
	resp, err := ts.TS.Client().Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("callback status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("callback content-type = %s", ct)
	}
	return pollCode
}

// TestOidcFullFlow 发起授权 → 假 provider → 回调 → 轮询成功 → 幂等绑定。
func TestOidcFullFlow(t *testing.T) {
	ts := newAuthServer(t)
	fp := newFakeProvider(t)
	seedProvider(t, ts, fp)

	// login-options：无 icon → 字符串数组形态。
	_, _, raw := doJSON(t, ts.TS.Client(), http.MethodGet, ts.TS.URL+"/api/login-options", nil, nil)
	var options []any
	if err := json.Unmarshal(raw, &options); err != nil || len(options) != 1 {
		t.Fatalf("login-options = %s (err %v)", raw, err)
	}
	if options[0] != "oidc/acme" {
		t.Errorf("login-options[0] = %v, want oidc/acme", options[0])
	}

	// 完整流：发起（携带设备信息）→ 回调。
	pollCode := runOidcFlow(t, ts, map[string]any{"deviceId": "dev-1", "deviceUuid": "uuid-1"})

	// 轮询：先 pending，回调后 success。
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodGet,
		ts.TS.URL+"/api/oidc/auth-query?code="+url.QueryEscape(pollCode), nil, nil)
	if status != 200 || parsed["status"] != "success" {
		t.Fatalf("auth-query should be success: %d %v", status, parsed)
	}
	oidcToken, _ := parsed["token"].(string)
	if oidcToken == "" {
		t.Fatal("auth-query missing token")
	}

	// OIDC 签发的面板 token 可访问受保护端点，payload 含绑定信息。
	status, _, raw = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/currentUser", nil, authHeader(oidcToken))
	if status != 200 {
		t.Fatalf("oidc token rejected: %d %s", status, raw)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["name"] != "oidcuser" || payload["third_auth_type"] != "oidc" {
		t.Errorf("oidc payload = %v", payload)
	}

	// 同一 subject 二次授权 → 幂等复用同一账号。
	pollCode2 := runOidcFlow(t, ts, nil)
	_, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodGet,
		ts.TS.URL+"/api/oidc/auth-query?code="+url.QueryEscape(pollCode2), nil, nil)
	if parsed["status"] != "success" {
		t.Fatalf("second flow status = %v", parsed["status"])
	}
	var count int64
	if err := ts.DB.Model(&entity.User{}).Where("username = ?", "oidcuser").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("oidc user duplicated: count = %d", count)
	}
}

// TestOidcUnknownProvider 未知提供商 → 404。
func TestOidcUnknownProvider(t *testing.T) {
	ts := newAuthServer(t)
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/oidc/auth",
		map[string]any{"provider": "ghost"}, nil)
	assertEnvelope(t, status, parsed, 404, "Provider not found")
}

// TestOidcAuthQueryUnknownCode 未知轮询 code → 404。
func TestOidcAuthQueryUnknownCode(t *testing.T) {
	ts := newAuthServer(t)
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodGet,
		ts.TS.URL+"/api/oidc/auth-query?code=ghost", nil, nil)
	assertEnvelope(t, status, parsed, 404, "Auth state not found")
}

// ---- 限流与清理 ----

// TestLoginRateLimit login 第 6 次 → 429 ThrottlerException 文案（共享知识 10）。
func TestLoginRateLimit(t *testing.T) {
	ts := newAuthServer(t)
	for i := 0; i < 5; i++ {
		status, _, _ := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login",
			map[string]any{"username": "databk", "password": "wrong"}, nil)
		if status != 401 {
			t.Fatalf("request %d status = %d, want 401", i+1, status)
		}
	}
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"username": "databk", "password": "wrong"}, nil)
	if status != 429 {
		t.Fatalf("request 6 status = %d, want 429 (body %s)", status, raw)
	}
	if msg, _ := parsed["message"].(string); !strings.Contains(msg, "ThrottlerException") {
		t.Errorf("message = %v, want ThrottlerException prefix", parsed["message"])
	}
}

// TestCleanupRunOnce 清理服务：过期 token/会话/授权态被清除。
func TestCleanupRunOnce(t *testing.T) {
	ts := newAuthServer(t)
	token := mustLogin(t, ts.TS, "databk", "databk")
	// 人为令 token 过期。
	if err := ts.DB.Model(&entity.UserToken{}).Where("1=1").
		Update("expiresAt", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	removed, err := ts.Router.Domain().Cleanup.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if removed < 1 {
		t.Fatalf("cleanup removed = %d, want >= 1", removed)
	}
	// 旧 token 已失效 → 401。
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/currentUser", nil, authHeader(token))
	assertEnvelope(t, status, parsed, 401, "Token expired or revoked")
}
