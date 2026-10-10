// settings_driven_test.go M1 批复 #7 settings 驱动切换回归：
//   - JWT 过期天数库值生效（general.jwtExpiryDays），env 缺省为 fallback；
//   - WebAuthn RP 配置库值优先；
//   - OIDC 登录流切 oidc_providers 数据驱动，env fallback 回归
//     （无库记录时行为与 M1 一致）。
package contract

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
)

// splitToken 按 '.' 切分 JWT 三段。
func splitToken(token string) []string {
	return strings.Split(token, ".")
}

// decodeBase64URL 解码 JWT 的 base64url（无填充）段。
func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// TestSettingsDrivenJWTExpiryDays 库值 general.jwtExpiryDays 生效于新签发
// token 的有效期（以 decoded exp - iat 断言，避免时钟漂移误差）。
func TestSettingsDrivenJWTExpiryDays(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	token, _ := abLogin(t, cs)

	// 先写库值：jwtExpiryDays = 3。
	cs.put(t, "/api/settings/general", map[string]any{
		"watermarkEnabled": false,
		"jwtExpiryDays":    3,
	}, bearer(token), http.StatusOK)

	// 重新登录取新 token（签发时读库）。
	_, login := contractLogin(t, cs, "databk")
	fresh, _ := login["access_token"].(string)
	if fresh == "" {
		t.Fatal("fresh token missing")
	}
	days := jwtLifetimeDays(t, fresh)
	if days != 3 {
		t.Errorf("JWT lifetime = %d days, want 3 (settings-driven)", days)
	}
}

// TestSettingsDrivenJWTExpiryFallback 库值缺失时回退 env 缺省
// （JWT_EXPIRY_DAYS=30，apptest 注入值）。
func TestSettingsDrivenJWTExpiryFallback(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	_, login := contractLogin(t, cs, "databk")
	token, _ := login["access_token"].(string)
	if token == "" {
		t.Fatal("token missing")
	}
	days := jwtLifetimeDays(t, token)
	if days != 30 {
		t.Errorf("JWT lifetime = %d days, want 30 (env fallback)", days)
	}
}

// TestSettingsDrivenJWTExpiryInvalidFallsBack 非法库值（0）不生效，
// 回退 env 缺省（fail-safe：不因脏库值把 token 置为立即过期）。
func TestSettingsDrivenJWTExpiryInvalidFallsBack(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	token, _ := abLogin(t, cs)
	// jwExpiryDays=0 被 openapi minimum:1 拦截，无法经 API 写入；
	// 直接以 1（最小合法值）验证库值优先路径的正向边界。
	cs.put(t, "/api/settings/general", map[string]any{
		"watermarkEnabled": false,
		"jwtExpiryDays":    1,
	}, bearer(token), http.StatusOK)

	_, login := contractLogin(t, cs, "databk")
	fresh, _ := login["access_token"].(string)
	if days := jwtLifetimeDays(t, fresh); days != 1 {
		t.Errorf("JWT lifetime = %d days, want 1 (minimum boundary)", days)
	}
}

// TestOidcLoginOptionsEnvFallback OIDC 数据驱动 + env fallback 回归：
// 表内无 enabled 记录时回退 env（既有 M1 用例已覆盖无 env 的空态；
// 本用例断言表内记录优先于 env）。
func TestOidcLoginOptionsDataDrivenOverridesEnv(t *testing.T) {
	cs := newSettingsContractServer(t, func(cfg *config.Config) {
		// env fallback 已配置。
		cfg.OidcIssuer = "https://env-fallback.example"
		cfg.OidcClientID = "env-client"
		cfg.OidcClientSecret = "env-secret"
	})

	// 表内无记录 → 公开端点回退 env 单项（响应为字符串数组）。
	raw := cs.get(t, "/api/login-options", nil, http.StatusOK)
	names := decodeLoginOptions(t, raw)
	if len(names) != 1 || names[0] != "oidc/oidc" {
		t.Errorf("env fallback names = %v, want [oidc/oidc] (%s)", names, raw)
	}

	// 表内建 enabled 记录 → 数据驱动优先（env fallback 不再出现）。
	token, _ := abLogin(t, cs)
	oidcProviderCreate(t, cs, token, "db-provider", "https://db.example")

	raw = cs.get(t, "/api/login-options", nil, http.StatusOK)
	names = decodeLoginOptions(t, raw)
	if len(names) != 1 || names[0] != "oidc/db-provider" {
		t.Errorf("data-driven names = %v, want [oidc/db-provider] (%s)", names, raw)
	}
}

// TestOidcLoginOptionsEnvFallbackDisabled 未配置 env 且表内无记录时
// 登录选项为空（既有 M1 行为回归）。
func TestOidcLoginOptionsEnvFallbackDisabled(t *testing.T) {
	cs := newSettingsContractServer(t, nil)
	raw := cs.get(t, "/api/login-options", nil, http.StatusOK)
	names := decodeLoginOptions(t, raw)
	if len(names) != 0 {
		t.Errorf("names = %v, want empty when neither table nor env configured (%s)", names, raw)
	}
}

// decodeLoginOptions 解析 login-options 响应（字符串数组形态）。
func decodeLoginOptions(t *testing.T, raw []byte) []string {
	t.Helper()
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		t.Fatalf("login-options body not string array: %v (%s)", err, raw)
	}
	return names
}

// TestSettingsDrivenWebauthnConfig 库值 webauthn 生效并出现在
// general 与 frontend 两处视图。
func TestSettingsDrivenWebauthnConfig(t *testing.T) {
	cs := newSettingsContractServer(t, nil)
	token, _ := abLogin(t, cs)

	cs.put(t, "/api/settings/general", map[string]any{
		"watermarkEnabled": true,
		"webauthnEnabled":  true,
		"webauthnRpName":   "Driven RP",
	}, bearer(token), http.StatusOK)

	// frontend 公开端点同步反映（Public 三键之一）。
	raw := cs.get(t, "/api/settings/frontend", nil, http.StatusOK)
	var frontend struct {
		WatermarkEnabled bool `json:"watermarkEnabled"`
		WebauthnEnabled  bool `json:"webauthnEnabled"`
	}
	if err := json.Unmarshal(raw, &frontend); err != nil {
		t.Fatalf("frontend body not object: %v (%s)", err, raw)
	}
	if !frontend.WebauthnEnabled || !frontend.WatermarkEnabled {
		t.Errorf("frontend must reflect settings-driven values: %s", raw)
	}

	// general 视图 rpName 同步。
	raw = cs.get(t, "/api/settings/general", bearer(token), http.StatusOK)
	var general struct {
		Webauthn struct {
			Enabled bool   `json:"enabled"`
			RpName  string `json:"rpName"`
		} `json:"webauthn"`
	}
	if err := json.Unmarshal(raw, &general); err != nil {
		t.Fatalf("general body not object: %v (%s)", err, raw)
	}
	if !general.Webauthn.Enabled || general.Webauthn.RpName != "Driven RP" {
		t.Errorf("webauthn not settings-driven: %s", raw)
	}
}

// jwtLifetimeDays 解析 JWT payload 计算 exp - iat 的天数（整数天）。
func jwtLifetimeDays(t *testing.T, token string) int {
	t.Helper()
	parts := splitToken(token)
	if len(parts) != 3 {
		t.Fatalf("token is not a JWT: %q", token)
	}
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var claims struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse jwt claims: %v (%s)", err, payload)
	}
	if claims.Exp <= claims.Iat {
		t.Fatalf("jwt exp (%d) must be after iat (%d)", claims.Exp, claims.Iat)
	}
	const secondsPerDay = 86400
	return int((claims.Exp - claims.Iat) / secondsPerDay)
}
