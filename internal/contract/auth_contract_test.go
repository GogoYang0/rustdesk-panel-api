// auth_contract_test.go 认证域契约用例：以 openapi.yaml 为准绳，
// 对 T04 全部认证端点做请求/响应双向校验（M1 验收：契约用例全通过）。
package contract

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/server"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// bearer Bearer 请求头。
func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// newAuthContractServer 全栈契约服务器：真实路由 + 内存库 +
// 禁限流（多步登录用例会超 login 5/min 配额，限流行为由
// TestLoginRateLimit 专项覆盖）。
func newAuthContractServer(t *testing.T) (*contractServer, *apptest.AppServer) {
	t.Helper()
	as := apptest.NewAppServer(t, nil)
	// 契约路由独立构建（共享 as.DB），禁限流避免多步登录用例
	// 超 login 5/min 配额；限流行为由集成 TestLoginRateLimit 专项覆盖。
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

// contractLogin 以标准设备信息登录（契约校验响应形状）。
func contractLogin(t *testing.T, cs *contractServer, password string) (int, map[string]any) {
	t.Helper()
	raw := cs.post(t, "/api/login", map[string]any{
		"type": "account", "username": "databk", "password": password,
		"id": "dev-1", "uuid": "uuid-1",
		"deviceInfo": map[string]any{"name": "contract-web", "os": "linux", "type": "web"},
	}, nil, 200)
	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("login body not json: %v", err)
	}
	return len(raw), resp
}

// TestContractLoginAccount 登录成功：LoginResponse 形状 + snake_case payload。
func TestContractLoginAccount(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, resp := contractLogin(t, cs, "databk")
	if resp["type"] != "account" {
		t.Errorf("type = %v", resp["type"])
	}
	if tok, _ := resp["access_token"].(string); tok == "" {
		t.Error("access_token missing")
	}
	user, ok := resp["user"].(map[string]any)
	if !ok {
		t.Fatalf("user missing: %v", resp)
	}
	for _, key := range []string{"guid", "name", "is_admin"} {
		if _, has := user[key]; !has {
			t.Errorf("user.%s missing (required by spec)", key)
		}
	}
	if user["has_password"] != true || user["tfa_enabled"] != false {
		t.Errorf("user flags = %v", user)
	}
}

// TestContractLogin401 错误密码 → 401 包络（纯文本 message）。
func TestContractLogin401(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	raw := cs.post(t, "/api/login", map[string]any{
		"type": "account", "username": "databk", "password": "wrong",
	}, nil, 401)
	assertEnvelopeShape(t, raw, 401)
	var env struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &env)
	if env.Message != "Username or password is incorrect" {
		t.Errorf("message = %q", env.Message)
	}
}

// TestContractLogin400 缺字段 → 400 包络（对象形态 message）。
func TestContractLogin400(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	raw := cs.post(t, "/api/login", map[string]any{"username": "only-user"}, nil, 400)
	assertEnvelopeShape(t, raw, 400)
	var env struct {
		Message map[string]any `json:"message"`
	}
	_ = json.Unmarshal(raw, &env)
	if env.Message == nil || env.Message["error"] != "Username and password are required" {
		t.Errorf("message.error = %v", env.Message)
	}
}

// TestContractLoginSmsCode400 sms_code 分支 → 400 未开放。
func TestContractLoginSmsCode400(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	raw := cs.post(t, "/api/login", map[string]any{
		"type": "sms_code", "username": "databk", "password": "databk",
	}, nil, 400)
	assertEnvelopeShape(t, raw, 400)
}

// TestContractLoginOptions GET /api/login-options → 200 数组。
func TestContractLoginOptions(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	raw := cs.get(t, "/api/login-options", nil, 200)
	var options []any
	if err := json.Unmarshal(raw, &options); err != nil {
		t.Fatalf("login-options not array: %v (%s)", err, raw)
	}
	if len(options) != 0 {
		t.Errorf("options = %v, want empty (no providers seeded)", options)
	}
}

// TestContractOidcAuth404 未知提供商 → 404 包络。
func TestContractOidcAuth404(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	raw := cs.post(t, "/api/oidc/auth", map[string]any{"provider": "ghost"}, nil, 404)
	assertEnvelopeShape(t, raw, 404)
}

// TestContractOidcAuthQuery404 未知轮询 code → 404 包络。
func TestContractOidcAuthQuery404(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	raw := cs.get(t, "/api/oidc/auth-query?code=ghost", nil, 404)
	assertEnvelopeShape(t, raw, 404)
}

// TestContractProtected401 未认证访问受保护端点 → 401 包络。
func TestContractProtected401(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	for _, path := range []string{
		"/api/currentUser", "/api/sessions", "/api/passkey/list", "/api/2fa/setup",
	} {
		method := "POST"
		if path == "/api/sessions" || path == "/api/passkey/list" {
			method = "GET"
		}
		raw := cs.raw(t, method, path, nil, nil, 401)
		assertEnvelopeShape(t, raw, 401)
	}
}

// TestContractCurrentUser 用户 payload 契约（snake_case，不泄敏感列）。
func TestContractCurrentUser(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)
	raw := cs.post(t, "/api/currentUser", nil, bearer(token), 200)
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

// TestContractSessionsLifecycle 会话列表/撤销/404 契约。
func TestContractSessionsLifecycle(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, first := contractLogin(t, cs, "databk")
	_, second := contractLogin(t, cs, "databk")
	token1 := first["access_token"].(string)
	token2 := second["access_token"].(string)

	raw := cs.get(t, "/api/sessions", bearer(token1), 200)
	var sessions []map[string]any
	if err := json.Unmarshal(raw, &sessions); err != nil {
		t.Fatalf("sessions not array: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions len = %d", len(sessions))
	}
	jti, _ := sessions[0]["jti"].(string)
	if jti == "" {
		t.Fatal("session jti missing")
	}
	for _, key := range []string{"createdAt", "expiresAt"} {
		if _, has := sessions[0][key]; !has {
			t.Errorf("session %s missing (required by spec)", key)
		}
	}

	// 撤销 token2 的会话 → 200 MessageResponse。
	cs.delete(t, "/api/sessions/"+jti, bearer(token1), 200)
	// 被撤销的 token2 立即 401。
	raw = cs.post(t, "/api/currentUser", nil, bearer(token2), 401)
	assertEnvelopeShape(t, raw, 401)
	// 撤销不存在 → 404 包络。
	raw = cs.delete(t, "/api/sessions/00000000-0000-4000-8000-000000000000", bearer(token1), 404)
	assertEnvelopeShape(t, raw, 404)
}

// TestContractLogout 登出 → 200 MessageResponse → 当前 token 401。
func TestContractLogout(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)
	cs.post(t, "/api/logout", map[string]any{"id": "dev-1", "uuid": "uuid-1"}, bearer(token), 200)
	raw := cs.post(t, "/api/currentUser", nil, bearer(token), 401)
	assertEnvelopeShape(t, raw, 401)
}

// TestContractTfaLifecycle setup/verify/disable 三端点契约。
func TestContractTfaLifecycle(t *testing.T) {
	cs, as := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)

	// setup → {secret, otpauth_url}。
	raw := cs.post(t, "/api/2fa/setup", nil, bearer(token), 200)
	var setup map[string]any
	if err := json.Unmarshal(raw, &setup); err != nil {
		t.Fatal(err)
	}
	secret, _ := setup["secret"].(string)
	if secret == "" {
		t.Fatalf("setup secret missing: %s", raw)
	}
	if _, has := setup["otpauth_url"]; !has {
		t.Error("otpauth_url missing (required by spec)")
	}

	// verify（用 pending secret 生成 6 位码）→ 200 MessageResponse。
	code, err := totp.GenerateCode(secret, contractClock())
	if err != nil {
		t.Fatal(err)
	}
	cs.post(t, "/api/2fa/verify", map[string]any{"tfaCode": code}, bearer(token), 200)

	// disable → 200 MessageResponse。
	code2, _ := totp.GenerateCode(secret, contractClock())
	cs.raw(t, "DELETE", "/api/2fa", map[string]any{"tfaCode": code2}, bearer(token), 200)
	_ = as
}

// contractClock 当前时间（TOTP 码生成用；独立函数便于语义表达）。
func contractClock() time.Time { return time.Now() }

// TestContractPasskeyRegister passkey 注册三端点契约
// （begin → verify → list），使用软件 authenticator。
func TestContractPasskeyRegister(t *testing.T) {
	cs, as := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)

	// begin → PublicKeyCredentialCreationOptionsJSON（开放对象）。
	raw := cs.post(t, "/api/passkey/register/begin", nil, bearer(token), 200)
	var begin map[string]any
	if err := json.Unmarshal(raw, &begin); err != nil {
		t.Fatal(err)
	}
	publicKey, _ := begin["publicKey"].(map[string]any)
	challenge, _ := publicKey["challenge"].(string)
	if challenge == "" {
		t.Fatalf("register begin missing challenge: %s", raw)
	}
	authr, err := testutil.NewSoftAuthenticator(as.Config.WebAuthnRPID, as.Config.WebAuthnOrigins[0], []byte("contract-guid"))
	if err != nil {
		t.Fatal(err)
	}
	regResp, err := authr.CreateRegistrationResponse(challenge)
	if err != nil {
		t.Fatal(err)
	}
	cs.post(t, "/api/passkey/register/verify", map[string]any{"response": regResp, "name": "contract-key"}, bearer(token), 200)

	// list → [PasskeyView]。
	raw = cs.get(t, "/api/passkey/list", bearer(token), 200)
	var views []map[string]any
	if err := json.Unmarshal(raw, &views); err != nil {
		t.Fatalf("passkey list not array: %v", err)
	}
	if len(views) != 1 || views[0]["name"] != "contract-key" {
		t.Errorf("views = %v", views)
	}
}

// TestContractPasskeyAuthBegin 免密登录发起契约（{secret, options}）。
func TestContractPasskeyAuthBegin(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	raw := cs.post(t, "/api/passkey/auth/begin", nil, nil, 200)
	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp["secret"].(string); !ok {
		t.Errorf("secret missing: %v", resp)
	}
	options, ok := resp["options"].(map[string]any)
	if !ok {
		t.Fatalf("options missing: %v", resp)
	}
	if _, ok := options["publicKey"].(map[string]any); !ok {
		t.Errorf("options.publicKey missing: %v", options)
	}
}

// TestContractPasskeyLifecycle passkey 免密登录全链路契约
// （补齐 passkeyTfaToggle / passkeyAuthVerify / deletePasskey 三个操作，
// 使 spec 全部 25 个 operation 均有契约用例覆盖 —— M1 退出标准）。
func TestContractPasskeyLifecycle(t *testing.T) {
	cs, as := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token := login["access_token"].(string)
	user, _ := login["user"].(map[string]any)
	userGuid, _ := user["guid"].(string)
	if userGuid == "" {
		t.Fatalf("login user.guid missing: %v", login)
	}

	// 注册 passkey：userHandle 必须为真实 guid（发现式登录比对 WebAuthnID）。
	authr, err := testutil.NewSoftAuthenticator(as.Config.WebAuthnRPID, as.Config.WebAuthnOrigins[0], []byte(userGuid))
	if err != nil {
		t.Fatal(err)
	}
	raw := cs.post(t, "/api/passkey/register/begin", nil, bearer(token), 200)
	var begin map[string]any
	if err := json.Unmarshal(raw, &begin); err != nil {
		t.Fatal(err)
	}
	challenge, _ := begin["publicKey"].(map[string]any)["challenge"].(string)
	regResp, err := authr.CreateRegistrationResponse(challenge)
	if err != nil {
		t.Fatal(err)
	}
	cs.post(t, "/api/passkey/register/verify", map[string]any{"response": regResp, "name": "contract-key"}, bearer(token), 200)

	// 开启 passkey 2FA → 200 MessageResponse（passkeyTfaToggle）。
	raw = cs.post(t, "/api/passkey/tfa", map[string]any{"enabled": true}, bearer(token), 200)
	var toggle map[string]any
	if err := json.Unmarshal(raw, &toggle); err != nil {
		t.Fatal(err)
	}
	if toggle["message"] == "" {
		t.Errorf("toggle message = %v", toggle)
	}

	// 密码登录第一步 → passkey_check 分支（开关生效的业务证据）。
	raw = cs.post(t, "/api/login", map[string]any{
		"type": "account", "username": "databk", "password": "databk",
	}, nil, 200)
	var step1 map[string]any
	if err := json.Unmarshal(raw, &step1); err != nil {
		t.Fatal(err)
	}
	if step1["tfa_type"] != "passkey_check" {
		t.Fatalf("tfa_type = %v, want passkey_check", step1["tfa_type"])
	}
	passkeyOptions, _ := step1["passkey_options"].(map[string]any)
	publicKey, _ := passkeyOptions["publicKey"].(map[string]any)
	stepSecret, _ := step1["secret"].(string)
	if publicKey == nil || stepSecret == "" {
		t.Fatalf("step1 missing passkey_options/secret: %v", step1)
	}

	// 第二步断言 → 200 LoginResponse account 分支（passkeyAuthVerify）。
	assertResp, err := authr.CreateAssertionResponse(publicKey["challenge"].(string))
	if err != nil {
		t.Fatal(err)
	}
	raw = cs.post(t, "/api/passkey/auth/verify", map[string]any{
		"secret": stepSecret, "response": assertResp,
		"id": "dev-1", "uuid": "uuid-1",
		"deviceInfo": map[string]any{"name": "contract-web", "os": "linux", "type": "web"},
	}, nil, 200)
	var step2 map[string]any
	if err := json.Unmarshal(raw, &step2); err != nil {
		t.Fatal(err)
	}
	if step2["type"] != "account" {
		t.Errorf("step2 type = %v", step2["type"])
	}
	if _, ok := step2["access_token"].(string); !ok {
		t.Errorf("step2 access_token missing: %v", step2)
	}

	// 凭据列表取 guid → 删除 → 200 MessageResponse（deletePasskey）。
	raw = cs.get(t, "/api/passkey/list", bearer(token), 200)
	var views []map[string]any
	if err := json.Unmarshal(raw, &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("views = %v", views)
	}
	guid, _ := views[0]["guid"].(string)
	if guid == "" {
		t.Fatal("passkey guid missing")
	}
	cs.delete(t, "/api/passkey/"+guid, bearer(token), 200)
}
