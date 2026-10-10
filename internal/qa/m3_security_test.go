// m3_security_test.go M3 全量安全矩阵独立验证（设计 §2
// qa/m3_security_test.go，T08 收口交付物）。
//
// 定位：M3 六域（用户/通讯录/审计/服务器/nexus/设置）落地后，以
// "全栈真实路由 + 真实中间件链" 复核提权面与跨租户面。与既有测试的
// 分工：
//
//	internal/contract/*          锁 openapi 请求/响应形状（契约校验）
//	internal/server/*            锁路由表 ↔ openapi ↔ 设计档位三方一致
//	internal/qa/m2_*_test.go     M2 域行为语义（设备/RBAC/用户组）
//	本文件                         M3 域提权与跨租户隔离矩阵（安全反例）
//
// 覆盖矩阵（四类攻击面）：
//
//	A. 提权矩阵：无权限/低权用户访问 Perm/AdminGuard/SuperAdmin 路由
//	   → 403 固定文案 + denied 审计落库（红线：拒绝必留痕）；
//	B. 用户域提权：users.batch/* 三码（status/security/force_logout）
//	   逐码拒绝、被禁用户 401、owner 账号不可禁用、跨用户伪造；
//	C. 资源归属隔离：nexus 构建跨用户访问（列表/取消/清单/下载）
//	   一律 404（不泄漏存在性）；通讯录 owner/规则并集 403；
//	D. 路径安全：nexus 产物 safeJoin 穿越族与 /files 静态同源语义，
//	   客户端文件名白名单前置拒绝（穿透面纵深防御）。
//
// 全部断言只经 HTTP 入口（不直接调服务层），确保中间件链顺序
// （RateLimit → JWTAuth → 策略决策 → handler）与真实运行一致。
package qa

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// ---- M3 安全测试基座 ----

// m3SecurityServer 禁限流全栈服务器 + M3 fixture（含 M2 基座）。
//
// 限流关闭的原因：安全矩阵逐个断言大量 4xx，per-route 限流（如
// settings test 5/min）会先于授权判定返回 429，掩盖目标语义。限流
// 本身由 ratelimit_test.go 专项覆盖。
func m3SecurityServer(t *testing.T) (*apptest.AppServer, *testutil.SeedM3Data) {
	t.Helper()
	as := newQAServerNoLimit(t)
	return as, testutil.SeedM3(t, as.DB)
}

// assertStatus 断言状态码并在不符时输出完整响应体（便于定位）。
func assertStatus(t *testing.T, label string, status, want int, raw []byte) {
	t.Helper()
	if status != want {
		t.Fatalf("%s: status = %d, want %d (body %s)", label, status, want, raw)
	}
}

// assertForbidden 断言 403 + 精确固定文案（共享知识 1：逐字节一致）。
func assertForbidden(t *testing.T, label string, status int, raw []byte, wantMsg string) {
	t.Helper()
	assertStatus(t, label, status, http.StatusForbidden, raw)
	var env struct {
		StatusCode int    `json:"statusCode"`
		Message    string `json:"message"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("%s: 403 包络非 JSON: %v (%s)", label, err, raw)
	}
	if env.Message != wantMsg {
		t.Errorf("%s: message = %q, want %q", label, env.Message, wantMsg)
	}
	if env.StatusCode != http.StatusForbidden {
		t.Errorf("%s: statusCode = %d, want 403", label, env.StatusCode)
	}
	if env.Error != http.StatusText(http.StatusForbidden) {
		t.Errorf("%s: error = %q, want %q", label, env.Error, http.StatusText(http.StatusForbidden))
	}
}

// assertNotFoundMsg 断言 404 + 精确文案。
func assertNotFoundMsg(t *testing.T, label string, status int, raw []byte, wantMsg string) {
	t.Helper()
	assertStatus(t, label, status, http.StatusNotFound, raw)
	var env struct {
		StatusCode int    `json:"statusCode"`
		Message    string `json:"message"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("%s: 404 包络非 JSON: %v (%s)", label, err, raw)
	}
	if env.Message != wantMsg {
		t.Errorf("%s: message = %q, want %q", label, env.Message, wantMsg)
	}
}

// assertUnauthorizedDisabled 断言被禁用户 401 + 固定文案。
func assertUnauthorizedDisabled(t *testing.T, label string, status int, raw []byte) {
	t.Helper()
	assertStatus(t, label, status, http.StatusUnauthorized, raw)
	if !strings.Contains(string(raw), rbac.MsgAccountDisabled) {
		t.Errorf("%s: message = %s, want %q", label, raw, rbac.MsgAccountDisabled)
	}
}

// assertDeniedAudited 断言某 (actor, code) 组合存在 denied 审计行
// （红线：授权拒绝必须落库 console_audits.result='denied'）。
func assertDeniedAudited(t *testing.T, as *apptest.AppServer, actorGuid, code, label string) {
	t.Helper()
	var count int64
	if err := as.DB.Model(&entity.ConsoleAudit{}).
		Where("actorUserGuid = ? AND result = ? AND action = ?",
			actorGuid, rbac.AuditResultDenied, code).
		Count(&count).Error; err != nil {
		t.Fatalf("%s: query denied audit: %v", label, err)
	}
	if count == 0 {
		t.Errorf("%s: denied 审计未落库 (actor=%s code=%s)", label, actorGuid, code)
	}
}

// grantM3 为角色补授权限码（构造 M3 域 scoped 操作者）。
func grantM3(t *testing.T, as *apptest.AppServer, roleGuid, code string) {
	t.Helper()
	row := entity.RolePermission{RoleGuid: roleGuid, PermissionCode: code}
	if err := as.DB.Create(&row).Error; err != nil {
		t.Fatalf("grantM3 %s: %v", code, err)
	}
}

// ---- A. 提权矩阵：Perm / AdminGuard / SuperAdmin 三档 ----

// TestM3SecurityPermDeniedAudited scoped 用户访问 servers 域
// Perm(servers.view) 路由 → 403 "Access denied" + denied 审计落库；
// 补授 servers.view 后同一路由放行（证明拒绝源于权限码而非路由错误）。
func TestM3SecurityPermDeniedAudited(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	// SeedM2 的 RoleDev 仅含 devices.view/disconnect，无 servers.view。
	label := "GET /api/servers (no servers.view)"
	status, _, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/servers", nil, scoped)
	assertForbidden(t, label, status, raw, rbac.MsgAccessDenied)
	assertDeniedAudited(t, as, seed.Scoped.Guid, rbac.CodeServersView, label)

	// 补授 servers.view → 同一端点放行（200），证明前次拒绝是权限决策。
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeServersView)
	label = "GET /api/servers (after grant servers.view)"
	status, _, raw = doJSON(t, client, http.MethodGet, as.TS.URL+"/api/servers", nil, scoped)
	assertStatus(t, label, status, http.StatusOK, raw)
}

// TestM3SecurityServersFiveCodeMatrix servers 域五码分档逐一复核：
// 低权操作者持有 servers.view 时，disconnect/config/control/ban 四条写/特
// 权路径仍逐条 403（权限码隔离，非"持 view 即通域"）。
func TestM3SecurityServersFiveCodeMatrix(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	// 仅授 view：验证同域内其余四码各自独立拒绝。
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeServersView)

	node := "qa-node"
	cases := []struct {
		label  string
		method string
		path   string
		code   string
	}{
		{"DELETE sessions/{uuid} (servers.disconnect)", http.MethodDelete, "/api/servers/" + node + "/sessions/sess-1", rbac.CodeServersDisconnect},
		{"GET services/hbbs/config (servers.config)", http.MethodGet, "/api/servers/" + node + "/services/hbbs/config", rbac.CodeServersConfig},
		{"PUT services/hbbs/config (servers.config)", http.MethodPut, "/api/servers/" + node + "/services/hbbs/config", rbac.CodeServersConfig},
		{"POST services/hbbs/start (servers.control)", http.MethodPost, "/api/servers/" + node + "/services/hbbs/start", rbac.CodeServersControl},
		{"GET bans (servers.ban)", http.MethodGet, "/api/servers/" + node + "/bans", rbac.CodeServersBan},
		{"PUT bans (servers.ban)", http.MethodPut, "/api/servers/" + node + "/bans", rbac.CodeServersBan},
	}
	for _, tc := range cases {
		var body any
		if tc.method == http.MethodPut && strings.HasSuffix(tc.path, "/config") {
			body = map[string]any{"values": map[string]any{"relay": "x"}}
		}
		if tc.method == http.MethodPut && strings.HasSuffix(tc.path, "/bans") {
			body = map[string]any{"device_ids": []string{"d1"}, "ips": []string{"10.0.0.1"}}
		}
		status, _, raw := doJSON(t, client, tc.method, as.TS.URL+tc.path, body, scoped)
		assertForbidden(t, tc.label, status, raw, rbac.MsgAccessDenied)
		assertDeniedAudited(t, as, seed.Scoped.Guid, tc.code, tc.label)
	}
}

// TestM3SecurityAdminGuardMatrix 设置域 / OIDC 提供者域 / 更新检查
// 共 19 条 AdminGuard 路由对非管理员逐一 403（文案
// "Access denied: administrator privileges required"）——非管理员即使
// 持有全部权限码亦不可越界（AdminGuard 与 Perm 是正交档位）。
func TestM3SecurityAdminGuardMatrix(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	// 补授全部相关权限码：证明 AdminGuard 拒绝不依赖权限码缺失。
	for _, code := range []string{
		rbac.CodeServersView, rbac.CodeAddressBooksView, rbac.CodeAddressBooksEdit,
		rbac.CodeAddressBooksShare, rbac.CodeAuditView, rbac.CodeUsersView,
		rbac.CodeUsersCreate, rbac.CodeUsersEdit, rbac.CodeUsersStatus,
		rbac.CodeUsersDelete, rbac.CodeUsersSecurity, rbac.CodeUsersForceLogout,
	} {
		grantM3(t, as, seed.RoleDev.Guid, code)
	}

	cases := []struct {
		label  string
		method string
		path   string
		body   any
	}{
		// —— 设置域 8 条（frontend 公开不在此列）——
		{"GET /api/settings/general", http.MethodGet, "/api/settings/general", nil},
		{"PUT /api/settings/general", http.MethodPut, "/api/settings/general", map[string]any{}},
		{"GET /api/settings/smtp", http.MethodGet, "/api/settings/smtp", nil},
		{"PUT /api/settings/smtp", http.MethodPut, "/api/settings/smtp", map[string]any{}},
		{"POST /api/settings/smtp/test", http.MethodPost, "/api/settings/smtp/test", map[string]any{}},
		{"GET /api/settings/ldap", http.MethodGet, "/api/settings/ldap", nil},
		{"PUT /api/settings/ldap", http.MethodPut, "/api/settings/ldap", map[string]any{}},
		{"POST /api/settings/ldap/test", http.MethodPost, "/api/settings/ldap/test", map[string]any{}},
		// —— OIDC 提供者域 8 条 ——
		{"GET /api/oidc-providers", http.MethodGet, "/api/oidc-providers", nil},
		{"POST /api/oidc-providers", http.MethodPost, "/api/oidc-providers", map[string]any{}},
		{"PATCH /api/oidc-providers/sort", http.MethodPatch, "/api/oidc-providers/sort", []string{}},
		{"GET /api/oidc-providers/{guid}", http.MethodGet, "/api/oidc-providers/qa-provider", nil},
		{"PATCH /api/oidc-providers/{guid}", http.MethodPatch, "/api/oidc-providers/qa-provider", map[string]any{}},
		{"DELETE /api/oidc-providers/{guid}", http.MethodDelete, "/api/oidc-providers/qa-provider", nil},
		{"PATCH /api/oidc-providers/{guid}/toggle", http.MethodPatch, "/api/oidc-providers/qa-provider/toggle", nil},
		{"POST /api/oidc-providers/{guid}/test", http.MethodPost, "/api/oidc-providers/qa-provider/test", nil},
		// —— 更新检查 1 条 ——
		{"GET /api/update-check", http.MethodGet, "/api/update-check", nil},
	}
	for _, tc := range cases {
		status, _, raw := doJSON(t, client, tc.method, as.TS.URL+tc.path, tc.body, scoped)
		assertForbidden(t, tc.label, status, raw, rbac.MsgAdminGuardRequired)
	}
}

// TestM3SecurityDashboardSuperAdminMatrix 仪表盘双端点 SuperAdmin 档：
// 非管理员 403 "Super administrator permission required"；管理员
// （isAdmin=1）放行 200。
func TestM3SecurityDashboardSuperAdminMatrix(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()

	scoped := authHeader(seedToken(t, as, seed.Scoped))
	for _, path := range []string{"/api/dashboard", "/api/dashboard/trends"} {
		label := "GET " + path + " (scoped)"
		status, _, raw := doJSON(t, client, http.MethodGet, as.TS.URL+path, nil, scoped)
		assertForbidden(t, label, status, raw, rbac.MsgSuperAdminRequired)
	}
	// RequireSuperAdmin 的 denied 审计 action = "super_admin"（非 "route"）。
	assertDeniedAudited(t, as, seed.Scoped.Guid, "super_admin", "GET /api/dashboard (scoped)")

	admin := authHeader(seedToken(t, as, seed.Admin))
	for _, path := range []string{"/api/dashboard", "/api/dashboard/trends"} {
		label := "GET " + path + " (admin)"
		status, _, raw := doJSON(t, client, http.MethodGet, as.TS.URL+path, nil, admin)
		assertStatus(t, label, status, http.StatusOK, raw)
	}
}

// TestM3SecurityUserDeleteProtectedTarget 用户删除路径的两级防护：
//
//  1. scoped 无 users.delete → 路由层 Perm 拒绝 403 "Access denied"
//     + denied 审计落库；
//  2. 补授 users.delete 后，目标为保护账号（持 protectedAccount 角色，
//     SeedM2 的 Owner）且操作者为非超管 → AssertUserMutation 403
//     "Protected accounts can only be modified by a super administrator"
//     （资源级复核，优先于"有码即通"）；
//  3. 反向对照：同一操作者对非保护目标（Global）放行 200，证明前次
//     拒绝源于目标行保护属性而非操作者无权限。
func TestM3SecurityUserDeleteProtectedTarget(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()

	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeUsersView)
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	// 第一步：无 users.delete → 路由层拒绝。
	label := "DELETE /api/users/{guid} (no users.delete)"
	status, _, raw := doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/users/"+seed.Owner.Guid, nil, scoped)
	assertForbidden(t, label, status, raw, rbac.MsgAccessDenied)
	assertDeniedAudited(t, as, seed.Scoped.Guid, rbac.CodeUsersDelete, label)

	// 第二步：补授后，保护账号复核接管。
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeUsersDelete)
	label = "DELETE /api/users/{guid} scoped→protected owner"
	status, _, raw = doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/users/"+seed.Owner.Guid, nil, scoped)
	assertForbidden(t, label, status, raw, rbac.MsgProtectedAccount)
	assertDeniedAudited(t, as, seed.Scoped.Guid, rbac.CodeUsersDelete, label)

	// 第三步：非保护目标放行（拒绝确源于保护属性）。
	label = "DELETE /api/users/{guid} scoped→global (allowed)"
	status, _, raw = doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/users/"+seed.Global.Guid, nil, scoped)
	assertStatus(t, label, status, http.StatusOK, raw)

	// 复核：Global 行已真实删除（非仅响应体宣称）。
	var remaining int64
	if err := as.DB.Model(&entity.User{}).
		Where("guid = ?", seed.Global.Guid).Count(&remaining).Error; err != nil {
		t.Fatalf("count deleted user: %v", err)
	}
	if remaining != 0 {
		t.Errorf("删除未落库: guid=%s 仍存在", seed.Global.Guid)
	}
}

// ---- B. 用户域提权矩阵（users.batch/* 三码）----

// TestM3SecurityUserBatchThreeCodeMatrix users.batch/{status,security,sessions}
// 三条批量路由的权限码隔离：scoped 无任一码时逐条 403 且各自 denied 审计
// 落库（三码不共用，防止"一码通三路"）。
func TestM3SecurityUserBatchThreeCodeMatrix(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	targets := []string{seed.Global.Guid}
	cases := []struct {
		label  string
		method string
		path   string
		code   string
		body   any
	}{
		{"PATCH /api/users/batch/status", http.MethodPatch, "/api/users/batch/status",
			rbac.CodeUsersStatus, map[string]any{"guids": targets, "status": 0}},
		{"PATCH /api/users/batch/security", http.MethodPatch, "/api/users/batch/security",
			rbac.CodeUsersSecurity, map[string]any{"guids": targets, "tfa_enforce": true}},
		{"DELETE /api/users/batch/sessions", http.MethodDelete, "/api/users/batch/sessions",
			rbac.CodeUsersForceLogout, map[string]any{"guids": targets}},
	}
	for _, tc := range cases {
		status, _, raw := doJSON(t, client, tc.method, as.TS.URL+tc.path, tc.body, scoped)
		assertForbidden(t, tc.label, status, raw, rbac.MsgAccessDenied)
		assertDeniedAudited(t, as, seed.Scoped.Guid, tc.code, tc.label)
	}
}

// TestM3SecurityDisabledUserProtectedDomains 被禁用户（status=0，JWT 有效）
// 访问 M3 域中 **带策略决策** 的端点（Perm/AdminGuard/SuperAdmin 三档）
// 一律 401 "Account does not exist or has been disabled"——策略决策入口
// 的 GetCurrentUser 实时状态复核先于权限判定，禁用即全量失效。
//
// 注意档位边界：Auth 档（如 nexus 域）不挂 RBAC 中间件，其状态复核归
// handler；故本用例仅覆盖策略决策档位，Auth 档另由
// TestM3SecurityDisabledUserAuthTierDocumented 显式记录既有语义。
func TestM3SecurityDisabledUserProtectedDomains(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	disabled := authHeader(seedToken(t, as, seed.Disabled))

	cases := []struct {
		label  string
		method string
		path   string
	}{
		{"GET /api/servers (perm:disabled)", http.MethodGet, "/api/servers"},
		{"GET /api/settings/general (admin_guard:disabled)", http.MethodGet, "/api/settings/general"},
		{"GET /api/oidc-providers (admin_guard:disabled)", http.MethodGet, "/api/oidc-providers"},
		{"GET /api/update-check (admin_guard:disabled)", http.MethodGet, "/api/update-check"},
		{"GET /api/audits/console (perm:disabled)", http.MethodGet, "/api/audits/console"},
		{"GET /api/audits/conn/active (perm:disabled)", http.MethodGet, "/api/audits/conn/active"},
		{"GET /api/users (perm:disabled)", http.MethodGet, "/api/users"},
		{"GET /api/dashboard (super_admin:disabled)", http.MethodGet, "/api/dashboard"},
	}
	for _, tc := range cases {
		status, _, raw := doJSON(t, client, tc.method, as.TS.URL+tc.path, nil, disabled)
		assertUnauthorizedDisabled(t, tc.label, status, raw)
	}
}

// TestM3SecurityDisabledUserAuthTierDocumented 记录 Auth 档的既有语义
// （非缺陷，属设计约定）：Auth 档仅要求 JWT 有效，状态复核下放 handler，
// 故被禁用户在 nexus 域读取路径上不会因 status=0 被中间件拦截。
//
// 本用例的价值是把该边界**显式化**：若未来把 nexus 域升格为 Perm 档，
// 此断言会失败并强制评审者同步更新安全矩阵。
func TestM3SecurityDisabledUserAuthTierDocumented(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	disabled := authHeader(seedToken(t, as, seed.Disabled))

	// Auth 档 + 无状态复核：被禁用户仍可通过 JWT 层（200 或业务 4xx，
	// 但绝不是 401 status-disabled 文案）。
	status, _, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/nexus/builds", nil, disabled)
	if status == http.StatusUnauthorized {
		t.Fatalf("nexus 域升格为状态复核档位？status=401 (%s)——请同步更新 m3_security 矩阵", raw)
	}
	if strings.Contains(string(raw), rbac.MsgAccountDisabled) {
		t.Fatalf("Auth 档不应由中间件产出 status-disabled 文案: %s", raw)
	}
	t.Logf("Auth 档语义确认: GET /api/nexus/builds (disabled 用户) → %d", status)
}

// TestM3SecurityNoTokenM3Domains 无 JWT 头访问 M3 受保护端点一律 401
// （不得因"无身份"落入 403 或直通）。公开端点
// （settings/frontend）与静态 /files 不在此列（另有正向断言）。
func TestM3SecurityNoTokenM3Domains(t *testing.T) {
	as, _ := m3SecurityServer(t)
	client := as.TS.Client()

	protected := []struct {
		label  string
		method string
		path   string
	}{
		{"GET /api/servers", http.MethodGet, "/api/servers"},
		{"GET /api/nexus/builds", http.MethodGet, "/api/nexus/builds"},
		{"GET /api/settings/general", http.MethodGet, "/api/settings/general"},
		{"GET /api/oidc-providers", http.MethodGet, "/api/oidc-providers"},
		{"GET /api/update-check", http.MethodGet, "/api/update-check"},
		{"GET /api/dashboard", http.MethodGet, "/api/dashboard"},
	}
	for _, tc := range protected {
		status, _, raw := doJSON(t, client, tc.method, as.TS.URL+tc.path, nil, nil)
		assertStatus(t, tc.label+" (no token)", status, http.StatusUnauthorized, raw)
	}

	// 公开端点正向：settings/frontend 无 JWT 也必须 200（不得被误保护）。
	status, _, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/settings/frontend", nil, nil)
	assertStatus(t, "GET /api/settings/frontend (public)", status, http.StatusOK, raw)
}

// ---- C. 资源归属与跨租户隔离 ----

// TestM3SecurityNexusCrossUserIsolation nexus 构建跨用户访问族：
// 非归属者访问他人构建的「取消 / 产物清单 / 产物下载」一律 404
// "Build task not found"（不泄漏资源存在性，优于 403）；且列表接口
// 不混入他人构建行。
func TestM3SecurityNexusCrossUserIsolation(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()

	// seed.Build1 归属 Scoped；Owner 为无绑定关系的第三方。
	owner := authHeader(seedToken(t, as, seed.Owner))
	buildUUID := seed.Build1.Uuid

	label := "DELETE /api/nexus/builds/{uuid} (cross-user)"
	status, _, raw := doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/nexus/builds/"+buildUUID, nil, owner)
	assertNotFoundMsg(t, label, status, raw, "Build task not found")

	label = "GET /api/nexus/builds/{uuid}/files (cross-user)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/nexus/builds/"+buildUUID+"/files", nil, owner)
	assertNotFoundMsg(t, label, status, raw, "Build task not found")

	label = "GET /api/nexus/builds/{uuid}/files/{filename} (cross-user)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/nexus/builds/"+buildUUID+"/files/agent.exe", nil, owner)
	assertNotFoundMsg(t, label, status, raw, "Build task not found")

	// 列表：Owner 视角不得含 Scoped 的 build1（行级归属过滤）。
	label = "GET /api/nexus/builds (owner view)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/nexus/builds", nil, owner)
	assertStatus(t, label, status, http.StatusOK, raw)
	var ownerBuilds []map[string]any
	if err := json.Unmarshal(raw, &ownerBuilds); err != nil {
		t.Fatalf("%s: 响应非 JSON 数组: %v (%s)", label, err, raw)
	}
	for _, b := range ownerBuilds {
		if u, _ := b["uuid"].(string); u == buildUUID {
			t.Errorf("%s: 列表泄漏他人构建 %s", label, buildUUID)
		}
	}

	// 归属者正向：同一构建 UUID 对 Scoped 返回 200（证明 404 源于归属）。
	scoped := authHeader(seedToken(t, as, seed.Scoped))
	label = "GET /api/nexus/builds/{uuid}/files (owner)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/nexus/builds/"+buildUUID+"/files", nil, scoped)
	assertStatus(t, label, status, http.StatusOK, raw)
}

// TestM3SecurityAddressBookShareIsolation 通讯录共享书隔离：
// Owner 的共享书 rule 授权只覆盖「scoped 用户 / seed-ug-1 组 / everyone」。
// Global 用户命中的是 everyone 档（RW=2），故：
//   - 读档位判定（READ=1）放行；
//   - FULL_CONTROL 档判定（ShareCandidates）403 "Full control permission
//     required"。
//
// 这条断言锁定"规则并集取最大值"语义：若并集被错误实现为交集或求和，
// 结果档位会漂移，本用例即失败。
func TestM3SecurityAddressBookShareIsolation(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	global := authHeader(seedToken(t, as, seed.Global))

	sharedGuid := seed.BookShared.Guid

	// 读路径：shared/{guid}/access 仅需 Auth，服务层复核 READ
	// （Everyone=RW(2) ≥ READ(1)）→ 200，且行内 rule 应回 everyone 档。
	label := "GET /api/ab/shared/{guid}/access (everyone rule)"
	status, _, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/ab/shared/"+sharedGuid+"/access", nil, global)
	assertStatus(t, label, status, http.StatusOK, raw)

	// 写路径：share-candidates 需 FULL_CONTROL（Everyone=RW(2) < 3）→ 403
	// "Full control permission required"。
	//
	// 路由档位为 Perm(address_books.share)，故先补授 share 及其依赖 view，
	// 使拒绝点落在服务层的规则档位而非路由权限码。
	grantM3(t, as, seed.RoleGlobal.Guid, rbac.CodeAddressBooksView)
	grantM3(t, as, seed.RoleGlobal.Guid, rbac.CodeAddressBooksShare)
	label = "GET /api/ab/shared/{guid}/share-candidates (everyone rule < full control)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/ab/shared/"+sharedGuid+"/share-candidates", nil, global)
	assertStatus(t, label, status, http.StatusForbidden, raw)
	if !strings.Contains(string(raw), "Full control permission required") {
		t.Errorf("%s: message = %s, want 含 'Full control permission required'", label, raw)
	}

	// 反向对照 A：Scoped 同书命中「用户规则 READ(1)」——FULL_CONTROL 仍
	// 不足 → 403；但 READ 档端点放行。证明 403 源于档位而非无任何授权。
	scoped := authHeader(seedToken(t, as, seed.Scoped))
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeAddressBooksView)
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeAddressBooksShare)

	label = "GET /api/ab/shared/{guid}/access (scoped user-rule read)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/ab/shared/"+sharedGuid+"/access", nil, scoped)
	assertStatus(t, label, status, http.StatusOK, raw)

	label = "GET /api/ab/shared/{guid}/share-candidates (scoped read < full control)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/ab/shared/"+sharedGuid+"/share-candidates", nil, scoped)
	assertStatus(t, label, status, http.StatusForbidden, raw)
	if !strings.Contains(string(raw), "Full control permission required") {
		t.Errorf("%s: message = %s, want 含 'Full control permission required'", label, raw)
	}

	// 反向对照 B：把 Scoped 归入 seed-ug-1 组后，「组规则 FULL_CONTROL(3)」
	// 命中，并集最大值由 READ(1) 抬升到 FULL_CONTROL(3) → 同一端点放行。
	// 这一步是"规则并集取最大值"的核心证据：若实现改为交集/最小值/
	// 求和，档位不会恰好等于 3，本断言即失败。
	//
	// 组归属经 users.userGroupGuid 判定（GroupGuidsOf），故须先落组行
	// （外键约束）再更新用户归属。
	ug := "seed-ug-1"
	if err := as.DB.Create(&entity.UserGroup{
		Guid: ug, Name: "seed group 1", NormalizedName: "seed group 1",
	}).Error; err != nil {
		t.Fatalf("create user group %s: %v", ug, err)
	}
	if err := as.DB.Model(&entity.User{}).
		Where("guid = ?", seed.Scoped.Guid).
		Update("userGroupGuid", ug).Error; err != nil {
		t.Fatalf("assign scoped to user group: %v", err)
	}
	label = "GET /api/ab/shared/{guid}/share-candidates (scoped union = full control)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/ab/shared/"+sharedGuid+"/share-candidates", nil, scoped)
	assertStatus(t, label, status, http.StatusOK, raw)
}

// TestM3SecurityAuditActiveScopedFiltering 审计 active 列表 scope 过滤
// （devices.disconnect 档）：全局操作者 can_disconnect 恒 true；
// scoped 操作者仅在其设备组内 uuid 上 can_disconnect=true，组外行为 false
// ——锁定"scope ∩ active"逐行判定，防止越组断连提权。
func TestM3SecurityAuditActiveScopedFiltering(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()

	// 全局操作者（RoleGlobal 仅 devices.view）：补授 disconnect 后为 global 档。
	grantM3(t, as, seed.RoleGlobal.Guid, rbac.CodeDevicesDisconnect)
	global := authHeader(seedToken(t, as, seed.Global))
	label := "GET /api/audits/conn/active (global)"
	status, _, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/audits/conn/active", nil, global)
	assertStatus(t, label, status, http.StatusOK, raw)
	var globalList struct {
		Data []struct {
			DeviceUuid    string `json:"device_uuid"`
			CanDisconnect bool   `json:"can_disconnect"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &globalList); err != nil {
		t.Fatalf("%s: 响应非 JSON 对象: %v (%s)", label, err, raw)
	}
	if len(globalList.Data) == 0 {
		t.Fatalf("%s: SeedM3 ConnActive 行应可见（fixture 未铺到？）", label)
	}
	for _, row := range globalList.Data {
		if !row.CanDisconnect {
			t.Errorf("%s: global scope 下 can_disconnect 应为 true (uuid=%s)", label, row.DeviceUuid)
		}
	}

	// scoped 操作者（devices.disconnect @ DG1）：SeedM3 的 ConnActive 挂
	// PeerA（DG1 内）→ can_disconnect=true，证明 scope 命中路径可用；
	// 越组行由 m2_qa_cascade 用例覆盖（PeerC@DG2 不在 active 集内）。
	scoped := authHeader(seedToken(t, as, seed.Scoped))
	label = "GET /api/audits/conn/active (scoped @ DG1)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/audits/conn/active", nil, scoped)
	assertStatus(t, label, status, http.StatusOK, raw)
	var scopedList struct {
		Data []struct {
			DeviceUuid    string `json:"device_uuid"`
			CanDisconnect bool   `json:"can_disconnect"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &scopedList); err != nil {
		t.Fatalf("%s: 响应非 JSON 对象: %v (%s)", label, err, raw)
	}
	for _, row := range scopedList.Data {
		if row.DeviceUuid != seed.PeerA.UUID {
			t.Errorf("%s: 可见越组设备 %s（期望仅 %s）", label, row.DeviceUuid, seed.PeerA.UUID)
		}
	}
}

// TestM3SecurityAuditViewDenied 审计查询域（audit.view 档）：
// scoped 无 audit.view 时 403 + denied 审计落库；补授后 200。
func TestM3SecurityAuditViewDenied(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	label := "GET /api/audits/console (no audit.view)"
	status, _, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/audits/console", nil, scoped)
	assertForbidden(t, label, status, raw, rbac.MsgAccessDenied)
	assertDeniedAudited(t, as, seed.Scoped.Guid, rbac.CodeAuditView, label)

	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeAuditView)
	label = "GET /api/audits/console (after grant audit.view)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/audits/console", nil, scoped)
	assertStatus(t, label, status, http.StatusOK, raw)
}

// ---- D. 路径安全（safeJoin 穿越族与文件名白名单）----

// TestM3SecurityNexusFilenameTraversal nexus 产物下载文件名白名单与
// safeJoin 纵深防御：穿越族 / 头注入族 / 纯点集一律 400 "Invalid path"
// （handler 层白名单前置拒绝），不触达文件系统读取。
func TestM3SecurityNexusFilenameTraversal(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))
	base := as.TS.URL + "/api/nexus/builds/" + seed.Build1.Uuid + "/files/"

	// 全部穿越/注入变体：URL 编码后仍须被白名单拒绝。
	bad := []struct {
		label string
		path  string
	}{
		{"dotdot plain", ".."},
		{"dotdot file", "../secret.txt"},
		{"dotdot deep", "....//....//etc/passwd"},
		{"triple dot", "..."},
		{"absolute slash", "%2Fetc%2Fpasswd"},
		{"backslash", "..%5C..%5Cwindows%5Cwin.ini"},
		{"null byte", "agent%00.exe"},
		{"crlf injection", "agent%0d%0aX-Injected%3A%20yes.exe"},
		{"quote injection", "agent%22evil.exe"},
		{"leading dot", ".hidden"},
		{"leading space", "%20agent.exe"},
		{"empty", ""},
	}
	for _, tc := range bad {
		label := "GET nexus artifact filename " + tc.label
		status, _, raw := doJSON(t, client, http.MethodGet, base+tc.path, nil, scoped)
		if status != http.StatusBadRequest && status != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 400/404 (body %s)", label, status, raw)
			continue
		}
		// 400 必须是固定文案 Invalid path；404 表示路由层已无匹配段。
		if status == http.StatusBadRequest && !strings.Contains(string(raw), "Invalid path") {
			t.Errorf("%s: message = %s, want 含 'Invalid path'", label, raw)
		}
	}
}

// TestM3SecurityFilesSafeJoinTraversal /files 静态路由（公开档）与 nexus
// 产物共用 safeJoin 语义（共享知识 25）：穿越族 → 400 "Invalid path"；
// 不存在的合法路径 → 404（不泄漏根目录布局）。
func TestM3SecurityFilesSafeJoinTraversal(t *testing.T) {
	as, _ := m3SecurityServer(t)
	client := as.TS.Client()
	base := as.TS.URL + "/files/"

	// 穿越变体：期望 400 Invalid path。
	traversal := []struct {
		label string
		path  string
	}{
		{"dotdot", "..%2Fsecret.txt"},
		{"dotdot deep", "....%2F....%2Fetc%2Fpasswd"},
		{"absolute", "%2Fetc%2Fpasswd"},
	}
	for _, tc := range traversal {
		label := "GET /files/ " + tc.label
		status, _, raw := doJSON(t, client, http.MethodGet, base+tc.path, nil, nil)
		if status != http.StatusBadRequest && status != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 400/404 (body %s)", label, status, raw)
			continue
		}
		if status == http.StatusBadRequest && !strings.Contains(string(raw), "Invalid path") {
			t.Errorf("%s: message = %s, want 含 'Invalid path'", label, raw)
		}
	}

	// 合法但不存在 → 404 File not found（无穿越 → 不返回 400）。
	label := "GET /files/ nonexistent"
	status, _, raw := doJSON(t, client, http.MethodGet,
		base+"build-not-exist/agent.exe", nil, nil)
	assertStatus(t, label, status, http.StatusNotFound, raw)
	if !strings.Contains(string(raw), "File not found") {
		t.Errorf("%s: message = %s, want 含 'File not found'", label, raw)
	}
}

// ---- E. 设置域敏感列掩码（提权面：读接口不泄漏明文密钥）----

// TestM3SecuritySettingsSecretMasking 设置域读接口对敏感列恒回掩码
// '******'：管理员写入明文后回读亦为掩码（凭据不回传），且以掩码值
// PUT 回写时不覆盖既有密文（掩码跳过语义，防止误清空）。
//
// 字段名对齐 openapi SmtpConfig（pass 而非 password）。
func TestM3SecuritySettingsSecretMasking(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))

	const plaintext = "super-secret-password"

	// 写入 SMTP 明文口令。
	label := "PUT /api/settings/smtp"
	status, _, raw := doJSON(t, client, http.MethodPut, as.TS.URL+"/api/settings/smtp",
		map[string]any{
			"host":     "smtp.example.com",
			"port":     587,
			"secure":   false,
			"user":     "mailer",
			"pass":     plaintext,
			"from":     "panel@example.com",
			"enabled":  true,
		}, admin)
	assertStatus(t, label, status, http.StatusOK, raw)

	// 回读：pass 必须为掩码，且响应体字节中不得出现明文。
	label = "GET /api/settings/smtp"
	status, parsed, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/settings/smtp", nil, admin)
	assertStatus(t, label, status, http.StatusOK, raw)
	if strings.Contains(string(raw), plaintext) {
		t.Fatalf("%s: 响应体泄漏 SMTP 明文口令", label)
	}
	if got, _ := parsed["pass"].(string); got != "******" {
		t.Errorf("%s: pass = %v, want '******'", label, parsed["pass"])
	}

	// 以掩码回写（未改口令）→ 库内密文保持原文。
	label = "PUT /api/settings/smtp (mask skip)"
	status, _, raw = doJSON(t, client, http.MethodPut, as.TS.URL+"/api/settings/smtp",
		map[string]any{
			"host":    "smtp.example.com",
			"port":    587,
			"secure":  false,
			"user":    "mailer",
			"pass":    "******",
			"from":    "panel@example.com",
			"enabled": true,
		}, admin)
	assertStatus(t, label, status, http.StatusOK, raw)

	var stored entity.SystemSetting
	if err := as.DB.Where("key = ?", "smtp.pass").First(&stored).Error; err != nil {
		t.Fatalf("read smtp.pass setting: %v", err)
	}
	if stored.Value != plaintext {
		t.Errorf("mask-skip 失效：库内 smtp.pass = %q, want %q", stored.Value, plaintext)
	}
}

// ---- F. 覆盖契约语句级核对辅助 ----

// TestM3SecurityRouteSurfaceCount 安全矩阵覆盖面自检：M3 六域受保护端点
// 无一遗漏 JWT——以路由表声明为准，Perm/AdminGuard/SuperAdmin 三档端点
// 总数必须与设计策略总表一致（164 operation 中扣除公开档）。
//
// 本用例读 Router.Routes() 声明（与三方一致性测试同源），断言"不存在
// 策略档位为空串的受保护路由"（即无漏挂中间件的端点）。
func TestM3SecurityRouteSurfaceCount(t *testing.T) {
	as, _ := m3SecurityServer(t)

	const (
		policyPublic     = "public"
		policyAuth       = "auth"
		policyPerm       = "perm"
		policyAdminGuard = "admin_guard"
		policySuperAdmin = "super_admin"
	)
	validPolicies := map[string]bool{
		policyPublic: true, policyAuth: true, policyPerm: true,
		policyAdminGuard: true, policySuperAdmin: true,
	}

	counts := map[string]int{}
	var total int
	for _, r := range as.Router.Routes() {
		total++
		if !validPolicies[r.Policy] {
			t.Errorf("route %s %s: 未知策略档位 %q", r.Method, r.Pattern, r.Policy)
			continue
		}
		counts[r.Policy]++
		// Perm 档必须有权限码；其余档位必须无码（互斥声明）。
		switch r.Policy {
		case policyPerm:
			if r.Code == "" {
				t.Errorf("route %s %s: perm 档缺少权限码", r.Method, r.Pattern)
			}
		default:
			if r.Code != "" {
				t.Errorf("route %s %s: %s 档不应携带权限码 %q", r.Method, r.Pattern, r.Policy, r.Code)
			}
		}
	}

	if total != 172 {
		t.Errorf("受保护+公开路由总数 = %d, want 172（设计 §1.3 策略总表 + GAP2 §2.3/§3）", total)
	}
	if counts[policyPublic] == 0 || counts[policyPerm] == 0 || counts[policyAdminGuard] == 0 {
		t.Errorf("档位分布异常（应各档非零）: %v", counts)
	}
	// 安全矩阵覆盖的三个受保护档位合计 = 总数 - 公开档。
	protected := counts[policyAuth] + counts[policyPerm] + counts[policyAdminGuard] + counts[policySuperAdmin]
	if protected+counts[policyPublic] != total {
		t.Errorf("档位分档不自洽: protected=%d public=%d total=%d", protected, counts[policyPublic], total)
	}
	t.Logf("M3 路由档位分布: public=%d auth=%d perm=%d admin_guard=%d super_admin=%d (total=%d)",
		counts[policyPublic], counts[policyAuth], counts[policyPerm],
		counts[policyAdminGuard], counts[policySuperAdmin], total)
}

// TestM3SecurityPublicSurfaceClosed 公开档白名单封闭性：M3 引入的公开
// 端点必须恰为下列集合（新增公开端点即提权面扩张，本用例强制显式复核）。
// 任何未列入的公开路由都会失败，迫使评审者确认其公开必要性。
func TestM3SecurityPublicSurfaceClosed(t *testing.T) {
	as, _ := m3SecurityServer(t)

	// 设计档位表中标为 public 的端点全集（§1.3 + §2.1 认证域 + 静态）。
	expectedPublic := map[string]bool{
		"GET /api/healthz":            true,
		"POST /api/login":             true,
		"GET /api/login-options":      true,
		"POST /api/passkey/auth/begin":  true,
		"POST /api/passkey/auth/verify": true,
		"POST /api/oidc/auth":         true,
		"GET /api/oidc/auth-query":    true,
		"GET /api/oidc/callback":      true,
		"GET /api/avatars/{filename}": true,
		"POST /api/heartbeat":         true,
		"POST /api/sysinfo":           true,
		"POST /api/audit/conn":        true,
		"POST /api/audit/file":        true,
		"POST /api/audit/alarm":       true,
		"POST /api/invitations/verify": true,
		"POST /api/invitations/accept": true,
		"GET /api/settings/frontend":  true,
		"GET /":                       true,
		"GET /files/{path}":           true,
		// GAP2 强制 MFA 绑定（公开凭 mfa_enroll 步会话 secret；设计 §3.2）。
		"POST /api/auth/mfa/enroll":        true,
		"POST /api/auth/mfa/enroll/verify": true,
	}

	actualPublic := map[string]bool{}
	for _, r := range as.Router.Routes() {
		if r.Policy == "public" {
			actualPublic[r.Method+" "+r.Pattern] = true
		}
	}

	for key := range actualPublic {
		if !expectedPublic[key] {
			t.Errorf("公开路由 %s 未在安全白名单中登记——新增公开端点须显式复核", key)
		}
	}
	for key := range expectedPublic {
		if !actualPublic[key] {
			t.Errorf("白名单公开路由 %s 未注册（契约漂移）", key)
		}
	}
	if len(expectedPublic) != len(actualPublic) {
		t.Errorf("公开档数量 = %d, want %d", len(actualPublic), len(expectedPublic))
	}
}

// TestM3SecurityEnvelopeShapeConsistency 错误包络形状一致性（M3 全域）：
// 403/404/401 三类拒绝的包络必须为 {statusCode, message, error} 三字段，
// 且 error 等于 HTTP 状态文本——防止 M3 handler 直接 writeHeader 裸写
// 而破坏前端统一错误处理。
func TestM3SecurityEnvelopeShapeConsistency(t *testing.T) {
	as, seed := m3SecurityServer(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	cases := []struct {
		label  string
		method string
		path   string
		body   any
		hdr    map[string]string
		want   int
	}{
		{"403 servers", http.MethodGet, "/api/servers", nil, scoped, http.StatusForbidden},
		{"401 no token", http.MethodGet, "/api/update-check", nil, nil, http.StatusUnauthorized},
		{"403 super admin", http.MethodGet, "/api/dashboard", nil, scoped, http.StatusForbidden},
		{"404 nexus cross-user", http.MethodGet,
			"/api/nexus/builds/" + seed.Build1.Uuid + "/files", nil,
			authHeader(seedToken(t, as, seed.Owner)), http.StatusNotFound},
	}
	for _, tc := range cases {
		status, parsed, raw := doJSON(t, client, tc.method, as.TS.URL+tc.path, tc.body, tc.hdr)
		assertStatus(t, tc.label, status, tc.want, raw)
		if got, _ := parsed["statusCode"].(float64); int(got) != tc.want {
			t.Errorf("%s: statusCode = %v, want %d", tc.label, parsed["statusCode"], tc.want)
		}
		if msg, _ := parsed["message"].(string); msg == "" {
			t.Errorf("%s: message 缺失 (body %s)", tc.label, raw)
		}
		if got, _ := parsed["error"].(string); got != http.StatusText(tc.want) {
			t.Errorf("%s: error = %q, want %q", tc.label, got, http.StatusText(tc.want))
		}
	}
}
