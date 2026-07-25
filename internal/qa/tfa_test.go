package qa

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// ---- 2FA：pending 状态隔离与错码可重试 ----

// wrongTfaCode 构造一个确定错误的 6 位验证码：与当前及 ±1 窗口的
// 正确码逐位对比后取异值，避免"恰好命中有效窗口"的 flaky。
func wrongTfaCode(t *testing.T, secret string) string {
	t.Helper()
	now := time.Now()
	codes := map[string]bool{}
	for _, off := range []int{-1, 0, 1} {
		code, err := totp.GenerateCode(secret, now.Add(time.Duration(off)*30*time.Second))
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		codes[code] = true
	}
	// 从 000000 起找第一个不在有效窗口码集合中的 6 位数字串。
	for i := 0; i < 1000000; i++ {
		candidate := fmt.Sprintf("%06d", i)
		if !codes[candidate] {
			return candidate
		}
	}
	t.Fatal("no invalid code found")
	return ""
}

// TestQATfaSetupPendingDoesNotActivate 任务指定高风险点：2fa/setup 之后
// 未 verify 时，2FA 必须不生效——tfaSecret 列不落库、info 仅存 pending、
// 用户重新登录仍一步直达 access_token（不触发两步验证）。
func TestQATfaSetupPendingDoesNotActivate(t *testing.T) {
	ts := newQAServerNoLimit(t)
	token := mustLogin(t, ts, "databk", "databk")

	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost,
		ts.TS.URL+"/api/2fa/setup", nil, authHeader(token))
	if status != 200 {
		t.Fatalf("setup status = %d: %s", status, raw)
	}
	pendingSecret, _ := parsed["secret"].(string)
	if pendingSecret == "" {
		t.Fatalf("setup secret missing: %s", raw)
	}

	// 未 verify：tfaSecret 列必须为空（pending 只允许存在于 info JSON）。
	var tfaSecret string
	if err := ts.DB.Raw("SELECT tfaSecret FROM users WHERE username = ?", "databk").Scan(&tfaSecret).Error; err != nil {
		t.Fatalf("read tfaSecret: %v", err)
	}
	if tfaSecret != "" {
		t.Fatalf("tfaSecret column = %q, want empty before verify", tfaSecret)
	}

	// 重新登录必须一步直达 account 响应，不得进入两步验证。
	status, parsed, raw = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/login", map[string]any{
		"username": "databk", "password": "databk",
	}, nil)
	if status != 200 {
		t.Fatalf("re-login status = %d: %s", status, raw)
	}
	if got, _ := parsed["type"].(string); got != "account" {
		t.Fatalf("re-login type = %v, want account (pending must not force two-step)", got)
	}
	if _, ok := parsed["access_token"].(string); !ok {
		t.Fatalf("re-login missing access_token: %s", raw)
	}
}

// TestQATfaVerifyWrongCodeKeepsPendingRetriable 任务指定高风险点：
// verify 错误验证码 → 401 "Invalid verification code"，且 pending 状态
// 必须保留（用户可重试），最终正确验证码可完成绑定。
func TestQATfaVerifyWrongCodeKeepsPendingRetriable(t *testing.T) {
	ts := newQAServerNoLimit(t)
	token := mustLogin(t, ts, "databk", "databk")

	// setup。
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost,
		ts.TS.URL+"/api/2fa/setup", nil, authHeader(token))
	if status != 200 {
		t.Fatalf("setup status = %d: %s", status, raw)
	}
	secret, _ := parsed["secret"].(string)

	// 错码 verify → 401。
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/2fa/verify",
		map[string]any{"tfaCode": wrongTfaCode(t, secret)}, authHeader(token))
	assertEnvelope(t, status, parsed, 401, "Invalid verification code")

	// pending 必须保留：info JSON 仍含 tfa_pending_secret。
	var info string
	if err := ts.DB.Raw("SELECT info FROM users WHERE username = ?", "databk").Scan(&info).Error; err != nil {
		t.Fatalf("read info: %v", err)
	}
	if !strings.Contains(info, "tfa_pending_secret") {
		t.Fatalf("pending secret lost after wrong code: info=%q", info)
	}

	// 重试正确验证码 → 绑定成功。
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, _, raw = doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/2fa/verify",
		map[string]any{"tfaCode": code}, authHeader(token))
	if status != 200 {
		t.Fatalf("retried verify status = %d: %s", status, raw)
	}

	// 绑定落库：tfaSecret 列等于 setup 返回的 secret。
	var bound string
	if err := ts.DB.Raw("SELECT tfaSecret FROM users WHERE username = ?", "databk").Scan(&bound).Error; err != nil {
		t.Fatalf("read bound tfaSecret: %v", err)
	}
	if bound != secret {
		t.Fatalf("tfaSecret bound = %q, want %q", bound, secret)
	}
}
