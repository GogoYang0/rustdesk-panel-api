// Package qa 是 QA 独立测试包（交付总监委派，M1 验收第 2 轮独立验证）。
//
// 定位：从用例设计视角补足工程师既有测试（internal/server、internal/contract）
// 未覆盖的高风险点，聚焦安全语义与会话状态机，不重复既有断言路径：
//
//	jwt_security_test.go   JWT 伪造签名/过期 exp/跨用户撤销越权/cookie 通道
//	login_session_test.go  login_sessions 状态机（过期行、used=1、单活跃替换）
//	tfa_test.go            2FA pending 不生效 / 错码后可重试绑定
//	ratelimit_test.go      并发 429 包络形状 / per-route 隔离端到端
//	avatar_test.go         头像字节回环 + 文件清理 / 穿越变体不泄漏
//
// 基建复用 internal/testutil/apptest（内存库 + 迁移 + 种子 + 全栈路由）。
package qa

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/pquerna/otp/totp"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// ---- 服务器构建 ----

// newQAServer 全栈服务器（默认开启限流）。
func newQAServer(t *testing.T) *apptest.AppServer {
	t.Helper()
	return apptest.NewAppServer(t, nil)
}

// newQAServerNoLimit 禁用限流（多步登录用例会超 login 5/min 配额；
// 限流行为由 ratelimit_test.go 专项覆盖）。
func newQAServerNoLimit(t *testing.T) *apptest.AppServer {
	t.Helper()
	return apptest.NewAppServer(t, func(c *config.Config) { c.RateLimitEnabled = false })
}

// ---- HTTP 辅助 ----

// doJSON 发送 JSON 请求，返回状态码、解析 map（仅对象响应）与原始字节。
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
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	parsed := map[string]any{}
	if len(raw) > 0 && strings.Contains(resp.Header.Get("Content-Type"), "json") {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			// 顶层数组响应（sessions / login-options / passkey list）合法，
			// 解析为数组后不填充 parsed，由用例直接消费 raw。
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

// mustLogin 登录成功返回 access_token，失败 Fatal。
func mustLogin(t *testing.T, ts *apptest.AppServer, username, password string) string {
	t.Helper()
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login", map[string]any{
		"username": username, "password": password,
	}, nil)
	if status != 200 {
		t.Fatalf("login %s status = %d: %s", username, status, raw)
	}
	token, _ := parsed["access_token"].(string)
	if token == "" {
		t.Fatalf("login %s: missing access_token: %s", username, raw)
	}
	return token
}

// assertEnvelope 断言错误包络三形态（statusCode/message/error）。
// wantMessage 非空时精确匹配 message；message 为对象/数组形态时传 ""。
func assertEnvelope(t *testing.T, status int, parsed map[string]any, wantStatus int, wantMessage string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status = %d, want %d (body %v)", status, wantStatus, parsed)
	}
	if got, _ := parsed["statusCode"].(float64); int(got) != wantStatus {
		t.Errorf("statusCode = %v, want %d", parsed["statusCode"], wantStatus)
	}
	if got, _ := parsed["error"].(string); got != http.StatusText(wantStatus) {
		t.Errorf("error = %v, want %q", parsed["error"], http.StatusText(wantStatus))
	}
	if wantMessage != "" {
		if got, _ := parsed["message"].(string); got != wantMessage {
			t.Errorf("message = %v, want %q", parsed["message"], wantMessage)
		}
	}
}

// ---- 数据构造辅助 ----

// userGuid 查询用户 guid。
func userGuid(t *testing.T, ts *apptest.AppServer, username string) string {
	t.Helper()
	var u entity.User
	if err := ts.DB.Where("username = ?", username).First(&u).Error; err != nil {
		t.Fatalf("find user %s: %v", username, err)
	}
	return u.Guid
}

// bindTfaSecret 直接向 DB 注入用户 TOTP secret（独立于 API 绑定流，
// 使 2FA 两步登录用例与 TfaService 绑定流程解耦）。
func bindTfaSecret(t *testing.T, ts *apptest.AppServer, username string) string {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "RustDesk", AccountName: username})
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	if err := ts.DB.Model(&entity.User{}).Where("username = ?", username).
		Update("tfaSecret", key.Secret()).Error; err != nil {
		t.Fatalf("bind tfaSecret: %v", err)
	}
	return key.Secret()
}

// insertSecondUser 复用种子管理员的 bcrypt hash 创建第二个普通用户，
// 避免测试内重复执行高成本 bcrypt 生成。
func insertSecondUser(t *testing.T, ts *apptest.AppServer) entity.User {
	t.Helper()
	var hash string
	if err := ts.DB.Raw("SELECT password FROM users WHERE username = ?", "databk").Scan(&hash).Error; err != nil || hash == "" {
		t.Fatalf("read seed password hash: %v (hash %q)", err, hash)
	}
	u := entity.User{
		Guid:      uuid.New().String(),
		Username:  "qasecond",
		Email:     "qasecond@panel.test",
		Password:  hash,
		Status:    1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := ts.DB.Create(&u).Error; err != nil {
		t.Fatalf("create second user: %v", err)
	}
	return u
}
