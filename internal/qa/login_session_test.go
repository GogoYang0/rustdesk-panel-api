package qa

import (
	"net/http"
	"testing"
	"time"
	"uuid"

	"github.com/pquerna/otp/totp"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// ---- 会话状态机：login_sessions（两步验证 5 分钟临时会话） ----

// beginTfaLogin 触发两步登录第一步，返回对外 secret（login_sessions.guid）。
func beginTfaLogin(t *testing.T, ts *apptest.AppServer, username, password string) string {
	t.Helper()
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login", map[string]any{
		"username": username, "password": password,
	}, nil)
	if status != 200 {
		t.Fatalf("tfa step1 status = %d: %s", status, raw)
	}
	if got, _ := parsed["type"].(string); got != "email_check" {
		t.Fatalf("tfa step1 type = %v, want email_check: %s", got, raw)
	}
	secret, _ := parsed["secret"].(string)
	if secret == "" {
		t.Fatalf("tfa step1 secret missing: %s", raw)
	}
	return secret
}

// completeTfaStep 提交两步第二步，返回状态码与解析响应。
func completeTfaStep(t *testing.T, ts *apptest.AppServer, secret, tfaCode string) (int, map[string]any) {
	t.Helper()
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login", map[string]any{
		"type": "tfa_code", "secret": secret, "tfaCode": tfaCode,
	}, nil)
	if status == 200 && parsed["access_token"] == nil {
		t.Fatalf("tfa step2 200 without access_token: %s", raw)
	}
	return status, parsed
}

// currentTfaCode 生成当前时刻的 TOTP 验证码。
func currentTfaCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return code
}

// TestQALoginSessionExpiredVerifyRejected 任务指定高风险点：login_sessions
// 过期后（DB 构造 expiresAt 过去行）即使验证码完全正确，verify 也必须 401，
// 且文案为"会话无效"而非"验证码错误"（两种 401 语义不同）。
func TestQALoginSessionExpiredVerifyRejected(t *testing.T) {
	ts := newQAServerNoLimit(t)
	secret := bindTfaSecret(t, ts, "databk")

	stepSecret := beginTfaLogin(t, ts, "databk", "databk")

	// 构造过期行：expiresAt 拨回 1 分钟前（FindUsable 的 expiresAt > now 不再命中）。
	if err := ts.DB.Model(&entity.LoginSession{}).
		Where("guid = ?", stepSecret).
		Update("expiresAt", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("expire login_session: %v", err)
	}

	status, parsed := completeTfaStep(t, ts, stepSecret, currentTfaCode(t, secret))
	assertEnvelope(t, status, parsed, 401, "Invalid or expired verification session")
}

// TestQALoginSessionUsedReplayRejected 任务指定高风险点：used=1 的会话
// 复用必须拒绝。与既有 TestTfaFullFlow 的"成功后复用 secret"路径不同，
// 本用例直接注入 used=1 行，隔离仓储 FindUsable 的 used 过滤语义。
func TestQALoginSessionUsedReplayRejected(t *testing.T) {
	ts := newQAServerNoLimit(t)
	secret := bindTfaSecret(t, ts, "databk")
	guid := userGuid(t, ts, "databk")

	replayed := uuid.New().String()
	if err := ts.DB.Create(&entity.LoginSession{
		Guid:      replayed,
		UserGuid:  guid,
		Method:    "tfa",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      true, // 已被消费
	}).Error; err != nil {
		t.Fatalf("seed used login_session: %v", err)
	}

	status, parsed := completeTfaStep(t, ts, replayed, currentTfaCode(t, secret))
	assertEnvelope(t, status, parsed, 401, "Invalid or expired verification session")
}

// TestQALoginSessionSingleActiveReplacement 单活跃语义：同一用户再次触发
// 两步登录时，DeleteExisting 清除旧会话 → 旧 secret 立即失效（401），
// 仅最新 secret 可完成登录。
func TestQALoginSessionSingleActiveReplacement(t *testing.T) {
	ts := newQAServerNoLimit(t)
	secret := bindTfaSecret(t, ts, "databk")

	oldSecret := beginTfaLogin(t, ts, "databk", "databk")
	newSecret := beginTfaLogin(t, ts, "databk", "databk")
	if oldSecret == newSecret {
		t.Fatal("two step1 logins must yield distinct secrets")
	}

	// 旧 secret 已被替换 → 401 会话无效。
	status, parsed := completeTfaStep(t, ts, oldSecret, currentTfaCode(t, secret))
	assertEnvelope(t, status, parsed, 401, "Invalid or expired verification session")

	// 最新 secret 正常完成 → 200 + access_token。
	status, parsed = completeTfaStep(t, ts, newSecret, currentTfaCode(t, secret))
	if status != 200 {
		t.Fatalf("newest secret verify = %d, want 200: %v", status, parsed)
	}
}
