// gap2_qa_test.go GAP2 独立攻击面用例（设计 §8 T5）：
//
//	assign 越权/越 scope 矩阵（devices.assign 与 device_group 档二次判定）
//	强制 MFA 绕过四象限（不强制+无2FA / 强制+无2FA / 强制+TOTP / 会话单次性）
//	login_audits best-effort 落库与 retention 清理（OQ-7）
//
// 与 contract/server 测试分工：本包聚焦安全反例与状态机边界，不做契约校验。
package qa

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/service/settings"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// ---- GAP2 基建 ----

// setMfaEnforceGlobal 直写 system_settings（mfa.enforceGlobal）。
func setMfaEnforceGlobal(t *testing.T, as *apptest.AppServer, enabled bool) {
	t.Helper()
	store := settings.NewStore(repository.NewSystemSettingRepo(as.DB))
	if err := store.SetBool(context.Background(), settings.KeyMfaEnforceGlobal, enabled, "mfa"); err != nil {
		t.Fatalf("set mfa.enforceGlobal: %v", err)
	}
}

// countLoginAudits 统计 login_audits 指定 result 行数。
func countLoginAudits(t *testing.T, as *apptest.AppServer, result string) int64 {
	t.Helper()
	var n int64
	if err := as.DB.Model(&entity.LoginAudit{}).Where("result = ?", result).Count(&n).Error; err != nil {
		t.Fatalf("count login_audits: %v", err)
	}
	return n
}

// ---- 设备个人归属 ----

// TestQAGap2AssignScopeMatrix assign 越权/越 scope 矩阵：
// 无码 403 → 授权后 DG1 内 200（落库+审计）→ 未分组 403 → 幽灵 404 →
// 幽灵用户 400 → 解绑置 NULL（action=device.unassign）。
func TestQAGap2AssignScopeMatrix(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()

	adminHdr := authHeader(seedToken(t, as, seed.Admin))
	scopedHdr := authHeader(seedToken(t, as, seed.Scoped))

	// 1) 未授权 devices.assign → 403 Access denied（路由 Perm 档拒绝）。
	status, parsed, raw := doJSON(t, client, http.MethodPatch,
		tsURL(as)+"/api/devices/"+seed.PeerA.UUID+"/assign",
		map[string]any{"userGuid": seed.Global.Guid}, scopedHdr)
	if status != http.StatusForbidden {
		t.Fatalf("no-code assign status = %d: %s", status, raw)
	}
	assertEnvelope(t, status, parsed, http.StatusForbidden, "Access denied")

	// 授权：RoleDev（Scoped 角色）补 devices.assign（requires 链要求
	// devices.view+users.view 全在，缺一即被生效码过滤）。
	grantQA(t, as, seed.RoleDev.Guid, "devices.assign")
	grantQA(t, as, seed.RoleDev.Guid, "users.view")

	// 2) DG1 内设备 → 200，peers.userGuid 落库 + console_audits 留痕。
	status, parsed, raw = doJSON(t, client, http.MethodPatch,
		tsURL(as)+"/api/devices/"+seed.PeerA.UUID+"/assign",
		map[string]any{"userGuid": seed.Global.Guid}, scopedHdr)
	if status != http.StatusOK {
		t.Fatalf("assign in-scope status = %d: %s", status, raw)
	}
	if got, _ := parsed["userGuid"].(string); got != seed.Global.Guid {
		t.Fatalf("assign resp userGuid = %v, want %s", parsed["userGuid"], seed.Global.Guid)
	}
	var dbUserGuid *string
	if err := as.DB.Raw("SELECT userGuid FROM peers WHERE uuid = ?", seed.PeerA.UUID).Scan(&dbUserGuid).Error; err != nil || dbUserGuid == nil || *dbUserGuid != seed.Global.Guid {
		t.Fatalf("peers.userGuid = %v (err=%v), want %s", dbUserGuid, err, seed.Global.Guid)
	}
	var audits []entity.ConsoleAudit
	if err := as.DB.Where("action = ?", "device.assign").Find(&audits).Error; err != nil || len(audits) == 0 {
		t.Fatalf("device.assign audit rows = %d (err=%v), want >=1", len(audits), err)
	}

	// 3) 未分组设备（PeerB）越出 scope → 403 Device is not in an authorized device group。
	status, parsed, raw = doJSON(t, client, http.MethodPatch,
		tsURL(as)+"/api/devices/"+seed.PeerB.UUID+"/assign",
		map[string]any{"userGuid": seed.Global.Guid}, scopedHdr)
	if status != http.StatusForbidden {
		t.Fatalf("out-of-scope assign status = %d: %s", status, raw)
	}
	assertEnvelope(t, status, parsed, http.StatusForbidden, "Device is not in an authorized device group")

	// 4) 幽灵设备 → 404 Device not found。
	status, parsed, raw = doJSON(t, client, http.MethodPatch,
		tsURL(as)+"/api/devices/ghost-uuid/assign",
		map[string]any{"userGuid": seed.Global.Guid}, adminHdr)
	if status != http.StatusNotFound {
		t.Fatalf("ghost device assign status = %d: %s", status, raw)
	}
	assertEnvelope(t, status, parsed, http.StatusNotFound, "Device not found")

	// 5) 幽灵用户 → 400 User not found。
	status, parsed, raw = doJSON(t, client, http.MethodPatch,
		tsURL(as)+"/api/devices/"+seed.PeerA.UUID+"/assign",
		map[string]any{"userGuid": "ghost-user-guid"}, adminHdr)
	if status != http.StatusBadRequest {
		t.Fatalf("ghost user assign status = %d: %s", status, raw)
	}
	assertEnvelope(t, status, parsed, http.StatusBadRequest, "User not found")

	// 6) 解绑（userGuid=null）→ 置 NULL + device.unassign 审计。
	status, _, raw = doJSON(t, client, http.MethodPatch,
		tsURL(as)+"/api/devices/"+seed.PeerA.UUID+"/assign",
		map[string]any{"userGuid": nil}, scopedHdr)
	if status != http.StatusOK {
		t.Fatalf("unassign status = %d: %s", status, raw)
	}
	if err := as.DB.Raw("SELECT userGuid FROM peers WHERE uuid = ?", seed.PeerA.UUID).Scan(&dbUserGuid).Error; err != nil || dbUserGuid != nil {
		t.Fatalf("peers.userGuid after unassign = %v (err=%v), want NULL", dbUserGuid, err)
	}
	var unassignRows int64
	if err := as.DB.Model(&entity.ConsoleAudit{}).Where("action = ?", "device.unassign").Count(&unassignRows).Error; err != nil || unassignRows == 0 {
		t.Fatalf("device.unassign audit rows = %d (err=%v), want >=1", unassignRows, err)
	}
}

// TestQAGap2MeDevicesAndUserDevices 我的设备（auth 档）与按用户反查
// （users.view）：越权 403、幽灵用户 404、精简视图无管理面字段。
func TestQAGap2MeDevicesAndUserDevices(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()

	adminHdr := authHeader(seedToken(t, as, seed.Admin))
	scopedHdr := authHeader(seedToken(t, as, seed.Scoped))

	// admin 把 PeerA 分配给 Scoped。
	status, _, raw := doJSON(t, client, http.MethodPatch,
		tsURL(as)+"/api/devices/"+seed.PeerA.UUID+"/assign",
		map[string]any{"userGuid": seed.Scoped.Guid}, adminHdr)
	if status != http.StatusOK {
		t.Fatalf("seed assign status = %d: %s", status, raw)
	}

	// 我的设备：仅自己名下，精简视图（不含 strategyGuid/userName 管理字段）。
	var parsed map[string]any
	status, parsed, raw = doJSON(t, client, http.MethodGet,
		tsURL(as)+"/api/users/me/devices?current=1&pageSize=20", nil, scopedHdr)
	if status != http.StatusOK {
		t.Fatalf("me/devices status = %d: %s", status, raw)
	}
	data, _ := parsed["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("me/devices rows = %d, want 1: %s", len(data), raw)
	}
	row, _ := data[0].(map[string]any)
	if row["uuid"] != seed.PeerA.UUID {
		t.Fatalf("me/devices uuid = %v, want %s", row["uuid"], seed.PeerA.UUID)
	}
	for _, banned := range []string{"strategyGuid", "userName", "deviceGroupName"} {
		if _, has := row[banned]; has {
			t.Errorf("me/devices row leaks management field %q", banned)
		}
	}

	// 按用户反查：Scoped 无 users.view → 403。
	status, parsed, raw = doJSON(t, client, http.MethodGet,
		tsURL(as)+"/api/users/"+seed.Scoped.Guid+"/devices?current=1&pageSize=20", nil, scopedHdr)
	if status != http.StatusForbidden {
		t.Fatalf("user/devices without users.view status = %d: %s", status, raw)
	}
	assertEnvelope(t, status, parsed, http.StatusForbidden, "Access denied")

	// admin（users.view）→ 200 且 total=1；幽灵用户 404。
	status, parsed, raw = doJSON(t, client, http.MethodGet,
		tsURL(as)+"/api/users/"+seed.Scoped.Guid+"/devices?current=1&pageSize=20", nil, adminHdr)
	if status != http.StatusOK {
		t.Fatalf("user/devices status = %d: %s", status, raw)
	}
	if got, _ := parsed["total"].(float64); int(got) != 1 {
		t.Fatalf("user/devices total = %v, want 1", parsed["total"])
	}
	status, _, raw = doJSON(t, client, http.MethodGet,
		tsURL(as)+"/api/users/ghost-guid/devices?current=1&pageSize=20", nil, adminHdr)
	if status != http.StatusNotFound {
		t.Fatalf("user/devices ghost status = %d: %s", status, raw)
	}
}

// ---- 强制 MFA ----

// TestQAGap2MfaEnforcementAndEnroll 强制 MFA 全流程：
// 策略关=直登 → 策略开=type=mfa_enroll → enroll 生成 → 错码 401 →
// 正码签发（tfaSecret 落库）→ 步会话单次性 → 再登走 email_check。
func TestQAGap2MfaEnforcementAndEnroll(t *testing.T) {
	ts := newQAServerNoLimit(t)
	client := ts.TS.Client()

	// 象限①：策略关 + 无 2FA → 直登 access_token。
	status, parsed, raw := doJSON(t, client, http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"username": "databk", "password": "databk"}, nil)
	if status != http.StatusOK {
		t.Fatalf("baseline login status = %d: %s", status, raw)
	}
	if got, _ := parsed["type"].(string); got != "access_token" {
		t.Fatalf("baseline login type = %v, want access_token", got)
	}
	if got := countLoginAudits(t, ts, "success"); got < 1 {
		t.Fatalf("login_audits success rows = %d, want >=1", got)
	}

	// 开启系统级强制。
	setMfaEnforceGlobal(t, ts, true)

	// 象限②：强制 + 无 2FA → type=mfa_enroll + secret（不返回 access_token）。
	status, parsed, raw = doJSON(t, client, http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"username": "databk", "password": "databk"}, nil)
	if status != http.StatusOK {
		t.Fatalf("enforced login status = %d: %s", status, raw)
	}
	if got, _ := parsed["type"].(string); got != "mfa_enroll" {
		t.Fatalf("enforced login type = %v, want mfa_enroll", got)
	}
	if _, leak := parsed["access_token"]; leak {
		t.Fatalf("mfa_enroll branch must not return access_token: %s", raw)
	}
	secret, _ := parsed["secret"].(string)
	if secret == "" {
		t.Fatalf("mfa_enroll secret missing: %s", raw)
	}
	if got := countLoginAudits(t, ts, "mfa_enroll_required"); got < 1 {
		t.Fatalf("login_audits mfa_enroll_required rows = %d, want >=1", got)
	}

	// enroll：生成 TOTP 绑定材料（pending secret 存会话 code 列）。
	status, parsed, raw = doJSON(t, client, http.MethodPost, ts.TS.URL+"/api/auth/mfa/enroll",
		map[string]any{"secret": secret}, nil)
	if status != http.StatusOK {
		t.Fatalf("enroll status = %d: %s", status, raw)
	}
	pending, _ := parsed["secret"].(string)
	otpauth, _ := parsed["otpauthUrl"].(string)
	if pending == "" || !strings.HasPrefix(otpauth, "otpauth://") {
		t.Fatalf("enroll result invalid: %s", raw)
	}

	// 错码 → 401 固定文案。
	status, parsed, raw = doJSON(t, client, http.MethodPost, ts.TS.URL+"/api/auth/mfa/enroll/verify",
		map[string]any{"secret": secret, "tfaCode": wrongTfaCode(t, pending)}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("enroll verify wrong-code status = %d: %s", status, raw)
	}
	assertEnvelope(t, status, parsed, http.StatusUnauthorized, "Invalid verification code")

	// 正码 → 签发 access_token + users.tfaSecret 落库 + 审计完成。
	code, err := totp.GenerateCode(pending, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	status, parsed, raw = doJSON(t, client, http.MethodPost, ts.TS.URL+"/api/auth/mfa/enroll/verify",
		map[string]any{"secret": secret, "tfaCode": code}, nil)
	if status != http.StatusOK {
		t.Fatalf("enroll verify status = %d: %s", status, raw)
	}
	token, _ := parsed["access_token"].(string)
	if token == "" {
		t.Fatalf("enroll verify missing access_token: %s", raw)
	}
	var tfaSecret string
	if err := ts.DB.Raw("SELECT tfaSecret FROM users WHERE username = ?", "databk").Scan(&tfaSecret).Error; err != nil || tfaSecret != pending {
		t.Fatalf("users.tfaSecret = %q (err=%v), want pending", tfaSecret, err)
	}
	if got := countLoginAudits(t, ts, "mfa_enroll_completed"); got < 1 {
		t.Fatalf("login_audits mfa_enroll_completed rows = %d, want >=1", got)
	}

	// 步会话单次性：同 secret 再 verify → 401 步会话无效。
	status, parsed, raw = doJSON(t, client, http.MethodPost, ts.TS.URL+"/api/auth/mfa/enroll/verify",
		map[string]any{"secret": secret, "tfaCode": code}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("replay verify status = %d: %s", status, raw)
	}
	assertEnvelope(t, status, parsed, http.StatusUnauthorized, "Invalid or expired verification session")

	// 象限③：已有 TOTP + 强制 → email_check（tfa_required），不被重复强制。
	status, parsed, raw = doJSON(t, client, http.MethodPost, ts.TS.URL+"/api/login",
		map[string]any{"username": "databk", "password": "databk"}, nil)
	if status != http.StatusOK {
		t.Fatalf("post-enroll login status = %d: %s", status, raw)
	}
	if got, _ := parsed["type"].(string); got != "email_check" {
		t.Fatalf("post-enroll login type = %v, want email_check", got)
	}
}

// TestQAGap2LoginAuditRetention login_audits 纳入 auditRetentionDays 清理
// （OQ-7）：30 天保留 → 100 天前旧行被清、新行保留；days<=0 不清理。
func TestQAGap2LoginAuditRetention(t *testing.T) {
	ts := newQAServerNoLimit(t)
	ctx := context.Background()

	store := settings.NewStore(repository.NewSystemSettingRepo(ts.DB))
	general := settings.NewGeneralService(store)
	if err := store.SetInt(ctx, settings.KeyGeneralAuditRetentionDay, 30, "general"); err != nil {
		t.Fatalf("set retention: %v", err)
	}
	repo := repository.NewLoginAuditRepo(ts.DB)
	old := time.Now().Add(-100 * 24 * time.Hour)
	for _, at := range []time.Time{old, time.Now()} {
		if err := repo.Create(ctx, &entity.LoginAudit{
			Guid:      newQAUUID(),
			Username:  "databk",
			Result:    entity.LoginAuditResultSuccess,
			Method:    entity.LoginAuditMethodPassword,
			CreatedAt: at,
		}); err != nil {
			t.Fatalf("seed login audit: %v", err)
		}
	}

	cleanup := authsvc.NewCleanupService(
		repository.NewUserTokenRepo(ts.DB),
		repository.NewLoginSessionRepo(ts.DB),
		repository.NewOidcRepo(ts.DB),
		nil,
	).WithLoginAuditRetention(repo, general)
	if _, err := cleanup.RunOnce(ctx); err != nil {
		t.Fatalf("cleanup run: %v", err)
	}

	var n int64
	if err := ts.DB.Model(&entity.LoginAudit{}).Count(&n).Error; err != nil {
		t.Fatalf("count after cleanup: %v", err)
	}
	if n != 1 {
		t.Fatalf("login_audits rows after cleanup = %d, want 1（旧行清、新行留）", n)
	}

	// days<=0（库值缺失 → fallback 不为正时）不清理：清空保留键置 0。
	if err := store.SetInt(ctx, settings.KeyGeneralAuditRetentionDay, 0, "general"); err != nil {
		t.Fatalf("set retention 0: %v", err)
	}
	if err := repo.Create(ctx, &entity.LoginAudit{
		Guid: newQAUUID(), Username: "x", Result: entity.LoginAuditResultFailed,
		Method: entity.LoginAuditMethodPassword, CreatedAt: old,
	}); err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	if _, err := cleanup.RunOnce(ctx); err != nil {
		t.Fatalf("cleanup run 2: %v", err)
	}
	if err := ts.DB.Model(&entity.LoginAudit{}).Where("username = ?", "x").Count(&n).Error; err != nil {
		t.Fatalf("count zero-retention: %v", err)
	}
	if n != 1 {
		t.Fatalf("retention=0 must keep rows, got %d", n)
	}
}

// newQAUUID 测试用随机 guid。
func newQAUUID() string {
	return strings.Replace(strings.ToLower(time.Now().Format("20060102150405.000000000")), ".", "-", 1) + "-qa"
}

// tsURL 服务器根 URL（doJSON 用绝对地址）。
func tsURL(as *apptest.AppServer) string { return as.TS.URL }

// 编译期引用守卫：testutil/SeedM2 在部分用例中经 m2Server 间接使用。
var _ = testutil.SeedM2
