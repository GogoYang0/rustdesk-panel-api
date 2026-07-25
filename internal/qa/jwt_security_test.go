package qa

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// ---- 安全：JWT 签名 / 过期 / 撤销复用 / 跨用户越权 ----

// seedActiveTokenRow 直插一条"未撤销未过期"的 user_tokens 行，
// 用于隔离单一防线（签名或 exp）的安全用例：撤销表侧是放行的，
// 被测请求若被拒绝，唯一原因必然是被测防线生效。
func seedActiveTokenRow(t *testing.T, ts *apptest.AppServer, userGuid, jti string) {
	t.Helper()
	row := &entity.UserToken{
		Guid:      jti,
		UserGuid:  userGuid,
		Jti:       jti,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := ts.DB.Create(row).Error; err != nil {
		t.Fatalf("seed user_tokens row: %v", err)
	}
}

// TestQAWrongSecretSignedTokenRejected 攻击者用自选密钥签发格式合法的
// HS256 JWT（sub/jti 指向真实活跃撤销记录）必须被 401 拒绝。
//
// 与既有 TestTamperedToken401（截断篡改签名尾段）互补：本用例保证
// "签名校验依赖服务端密钥"这一防线本身——撤销表记录完全合法，
// 唯一拦截手段是 HS256 验签。
func TestQAWrongSecretSignedTokenRejected(t *testing.T) {
	ts := newQAServerNoLimit(t)
	guid := userGuid(t, ts, "databk")
	jti := uuid.New().String()
	seedActiveTokenRow(t, ts, guid, jti)

	now := time.Now()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": guid, "username": "databk", "email": "databk@github.com",
		"isAdmin": true, "deviceId": "", "jti": jti,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}).SignedString([]byte("attacker-chosen-secret"))
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}

	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPost,
		ts.TS.URL+"/api/currentUser", nil, authHeader(signed))
	assertEnvelope(t, status, parsed, 401, "Token expired or revoked")
}

// TestQAExpiredJWTRejectedEvenWithActiveRecord 用正确密钥签发 exp 已过期的
// JWT，且撤销表中 (userGuid, jti) 记录仍处于"未撤销未过期"状态。
//
// 防线语义：JWT 层 exp 校验必须独立于 user_tokens 有状态校验——
// 即便有状态侧放行，exp 过期也必须 401。
func TestQAExpiredJWTRejectedEvenWithActiveRecord(t *testing.T) {
	ts := newQAServerNoLimit(t)
	guid := userGuid(t, ts, "databk")
	jti := uuid.New().String()
	seedActiveTokenRow(t, ts, guid, jti) // 撤销表侧：活跃

	now := time.Now()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": guid, "username": "databk", "email": "databk@github.com",
		"isAdmin": true, "deviceId": "", "jti": jti,
		"iat": now.Add(-2 * time.Hour).Unix(), "exp": now.Add(-time.Hour).Unix(),
	}).SignedString([]byte(ts.Config.JWTSecret))
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodPost,
		ts.TS.URL+"/api/currentUser", nil, authHeader(signed))
	assertEnvelope(t, status, parsed, 401, "Token expired or revoked")
}

// TestQACrossUserSessionRevokeIsForbidden 用户 A 尝试撤销用户 B 的
// 真实活跃会话。
//
// 实现语义记录：RevokeSession 先以 (当前用户 guid, 路径 jti) 查活跃
// 记录，查不到 → 404 "Session not found"（非 403）。本用例除断言 404
// 外，还必须验证无越权副作用：B 的会话未被误撤销、B 的 token 仍有效。
func TestQACrossUserSessionRevokeIsForbidden(t *testing.T) {
	ts := newQAServerNoLimit(t)

	tokenA := mustLogin(t, ts, "databk", "databk")
	victim := insertSecondUser(t, ts)
	tokenB := mustLogin(t, ts, victim.Username, "databk")

	// B 查出自己的活跃 jti。
	status, _, raw := doJSON(t, ts.TS.Client(), http.MethodGet,
		ts.TS.URL+"/api/sessions", nil, authHeader(tokenB))
	if status != 200 {
		t.Fatalf("victim sessions status = %d: %s", status, raw)
	}
	var sessions []map[string]any
	if err := json.Unmarshal(raw, &sessions); err != nil {
		t.Fatalf("sessions not array: %v (%s)", err, raw)
	}
	if len(sessions) != 1 {
		t.Fatalf("victim sessions len = %d, want 1", len(sessions))
	}
	jtiB, _ := sessions[0]["jti"].(string)
	if jtiB == "" {
		t.Fatal("victim jti missing")
	}

	// A 携带自己的 token 撤销 B 的 jti → 404。
	status, parsed, _ := doJSON(t, ts.TS.Client(), http.MethodDelete,
		ts.TS.URL+"/api/sessions/"+jtiB, nil, authHeader(tokenA))
	assertEnvelope(t, status, parsed, 404, "Session not found")

	// 无越权副作用：B 的 token 仍有效、会话仍在。
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodPost,
		ts.TS.URL+"/api/currentUser", nil, authHeader(tokenB))
	if status != 200 {
		t.Fatalf("victim token must survive: %d %v", status, parsed)
	}
	status, _, raw = doJSON(t, ts.TS.Client(), http.MethodGet,
		ts.TS.URL+"/api/sessions", nil, authHeader(tokenB))
	if status != 200 {
		t.Fatalf("victim sessions after failed revoke: %d %s", status, raw)
	}
	if err := json.Unmarshal(raw, &sessions); err != nil || len(sessions) != 1 {
		t.Fatalf("victim session must remain, got %s (err %v)", raw, err)
	}
}

// TestQACookieTokenChannelEndToEnd 受保护端点支持 cookie access_token
// 回退通道：无 Authorization 头时 cookie 携带有效 token → 200；
// 而 Bearer 头（即使无效）存在时优先级更高，无效 Bearer → 401。
func TestQACookieTokenChannelEndToEnd(t *testing.T) {
	ts := newQAServerNoLimit(t)
	token := mustLogin(t, ts, "databk", "databk")

	req, err := http.NewRequest(http.MethodPost, ts.TS.URL+"/api/currentUser", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.TS.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("cookie channel status = %d, want 200", resp.StatusCode)
	}

	// Bearer 优先：无效 Bearer 头 + 有效 cookie → 401。
	req2, err := http.NewRequest(http.MethodPost, ts.TS.URL+"/api/currentUser", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", "Bearer invalid-token")
	req2.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp2, err := ts.TS.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != 401 {
		t.Fatalf("bearer priority status = %d, want 401", resp2.StatusCode)
	}
}
