// m2_qa_rbac_matrix_test.go RBAC 越权矩阵独立用例（QA 第 2 轮补强，
// 避开 m2_rbac_security_test.go 已有断言路径）：
//
//	★JWT isAdmin=true 但 DB is_admin=false 不能绕过（查库不信任 token 红线）
//	零权限用户 × M2 各策略档位 403 全矩阵（Perm/AdminGuard/SuperAdmin 三文案）+ Auth 档对照
//	requires 链自动失效端到端（父权限码缺失 → 子权限码失效 → 补授恢复）
//	device_group scope 单目标跨组/未分组 403（PATCH note / DELETE / status）
package qa

import (
	"context"
	"net/http"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// spoofAdminToken 为 DB 中 is_admin=false 的用户签发 isAdmin=true 的 JWT
// （claims 与 DB 状态不一致——攻击者持有旧/篡改 token 的等效形态；
// 签发与登录共用 TokenService.Generate，保证签名/撤销表全部合法）。
func spoofAdminToken(t *testing.T, as *apptest.AppServer, user *entity.User) string {
	t.Helper()
	forged := *user
	forged.IsAdmin = true
	svc := authsvc.NewTokenService(repository.NewUserTokenRepo(as.DB), as.Config.JWTSecret, 1)
	tok, err := svc.Generate(context.Background(), &forged, dto.LoginDevice{
		Id: "qa-spoof", Uuid: "qa-spoof-uuid", Name: "qa", Os: "linux", Type: "web",
	})
	if err != nil {
		t.Fatalf("spoofAdminToken: %v", err)
	}
	return tok
}

// TestQAJwtIsAdminSpoofBlocked 红线验证：JWT claims isAdmin=true 的普通
// 用户在三条授权路线上全部被拒（决策一律实时查库），且 /peers 可见性
// 不因 claims 提权（仍按 DB is_admin 走受限查询）。
func TestQAJwtIsAdminSpoofBlocked(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	spoofed := authHeader(spoofAdminToken(t, as, seed.Scoped)) // DB is_admin=false

	// 1. SuperAdmin 路线 → 403 super administrator 文案。
	status, _, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/roles",
		map[string]any{"name": "qa-spoofed-role"}, spoofed)
	if status != http.StatusForbidden || !contains(raw, rbac.MsgSuperAdminRequired) {
		t.Errorf("roles create = %d %s, want 403 %q", status, raw, rbac.MsgSuperAdminRequired)
	}

	// 2. AdminGuard 路线 → 403 admin guard 文案。
	status, _, raw = doJSON(t, client, http.MethodGet, as.TS.URL+"/api/device-groups", nil, spoofed)
	if status != http.StatusForbidden || !contains(raw, rbac.MsgAdminGuardRequired) {
		t.Errorf("device-groups list = %d %s, want 403 %q", status, raw, rbac.MsgAdminGuardRequired)
	}

	// 3. Perm 路线：claims 不参与权限计算——roles.view 不在其角色码集
	// （claims isAdmin=true 若被信任将按 Global 放行 200）→ 必须 403。
	status, _, raw = doJSON(t, client, http.MethodGet, as.TS.URL+"/api/roles", nil, spoofed)
	if status != http.StatusForbidden || !contains(raw, rbac.MsgAccessDenied) {
		t.Errorf("roles list = %d %s, want 403 %q（claims 不得替代查库）", status, raw, rbac.MsgAccessDenied)
	}

	// 4. /peers 与 /devices 可见性：claims 不扩大 scope——仍只见授权组
	// 内 PeerA（total=1），而非管理员全量 3 台。
	status, resp, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/peers", nil, spoofed)
	if status != http.StatusOK {
		t.Fatalf("peers = %d (%s), want 200", status, raw)
	}
	if total, _ := resp["total"].(float64); total != 1 {
		t.Errorf("peers total = %v, want 1（isAdmin claim 不得扩大可见性）", resp["total"])
	}
	status, resp, raw = doJSON(t, client, http.MethodGet, as.TS.URL+"/api/devices", nil, spoofed)
	if status != http.StatusOK {
		t.Fatalf("devices = %d (%s), want 200", status, raw)
	}
	if total, _ := resp["total"].(float64); total != 1 {
		t.Errorf("devices total = %v, want 1（scope 仍为 DG1，不因 claims 变 global）", resp["total"])
	}
}

// TestQANoPermissionUserM2Matrix 零权限用户（无任何 assignment）× M2
// 三档授权路线 403 全矩阵 + Auth 档对照（无权限码端点放行）。
func TestQANoPermissionUserM2Matrix(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	bare := &entity.User{Guid: "qa-user-bare", Username: "qa-bare",
		Email: "qa-bare@example.com", Status: 1, CreatedAt: seed.Now, UpdatedAt: seed.Now}
	if err := as.DB.Create(bare).Error; err != nil {
		t.Fatalf("seed bare user: %v", err)
	}
	hdr := authHeader(seedToken(t, as, bare))

	// Perm 档：码不在任何指派 → 空 scope → 403 Access denied。
	for _, ep := range []struct{ method, path string }{
		{http.MethodGet, "/api/devices"},
		{http.MethodGet, "/api/strategies"},
		{http.MethodGet, "/api/user-groups"},
		{http.MethodGet, "/api/roles"},
		{http.MethodGet, "/api/permissions"},
	} {
		status, parsed, raw := doJSON(t, client, ep.method, as.TS.URL+ep.path, nil, hdr)
		if status != http.StatusForbidden {
			t.Errorf("%s %s = %d (%s), want 403", ep.method, ep.path, status, raw)
			continue
		}
		assertEnvelope(t, status, parsed, http.StatusForbidden, rbac.MsgAccessDenied)
	}

	// AdminGuard 档 → 403 administrator privileges required。
	status, parsed, _ := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/device-groups", nil, hdr)
	assertEnvelope(t, status, parsed, http.StatusForbidden, rbac.MsgAdminGuardRequired)
	status, parsed, _ = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/device-groups",
		map[string]any{"name": "qa-forbidden"}, hdr)
	assertEnvelope(t, status, parsed, http.StatusForbidden, rbac.MsgAdminGuardRequired)

	// SuperAdmin 档 → 403 super administrator。
	status, parsed, _ = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/roles",
		map[string]any{"name": "qa-forbidden"}, hdr)
	assertEnvelope(t, status, parsed, http.StatusForbidden, rbac.MsgSuperAdminRequired)
	status, parsed, _ = doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/roles/00000000-0000-4000-8000-000000000009", nil, hdr)
	assertEnvelope(t, status, parsed, http.StatusForbidden, rbac.MsgSuperAdminRequired)

	// Auth 档对照：无权限码端点不 403（/peers 空可见性、accessible 空、
	// permissions/me 空集）。
	var resp map[string]any
	status, resp, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/peers", nil, hdr)
	if status != http.StatusOK || resp["total"] != float64(0) {
		t.Errorf("bare /peers = %d %v (%s), want 200 total=0", status, resp["total"], raw)
	}
	status, _, raw = doJSON(t, client, http.MethodGet, as.TS.URL+"/api/device-group/accessible", nil, hdr)
	if status != http.StatusOK {
		t.Errorf("bare accessible = %d (%s), want 200", status, raw)
	}
	status, resp, raw = doJSON(t, client, http.MethodGet, as.TS.URL+"/api/permissions/me", nil, hdr)
	if status != http.StatusOK {
		t.Fatalf("permissions/me = %d (%s), want 200", status, raw)
	}
	if perms, _ := resp["permissions"].([]any); len(perms) != 0 {
		t.Errorf("bare permissions = %v, want []", resp["permissions"])
	}
}

// TestQARequiresChainParentRevokedChildInvalid requires 链自动失效
// 端到端：角色同时持有 devices.view+devices.edit，父码 devices.view
// 被移除（DB 直写模拟历史/运维脏数据——API 写路径已被 400 挡住，
// 单独补一发写路径防线断言）后 devices.edit 决策失效 → 补回即恢复。
func TestQARequiresChainParentRevokedChildInvalid(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))

	// API 写路径防线：仅授子码缺父码 → 400 Missing permission dependencies。
	status, _, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/roles",
		map[string]any{"name": "qa-child-only", "permissions": []string{rbac.CodeDevicesEdit}}, admin)
	if status != http.StatusBadRequest || !contains(raw, "Missing permission dependencies") {
		t.Fatalf("create child-only role = %d %s, want 400 Missing permission dependencies", status, raw)
	}

	// 经 API 合法建角色（父+子），指派给 child 用户（global）。
	status, resp, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/roles",
		map[string]any{"name": "qa-chain-role",
			"permissions": []string{rbac.CodeDevicesView, rbac.CodeDevicesEdit}}, admin)
	if status != http.StatusOK {
		t.Fatalf("create chain role = %d (%s)", status, raw)
	}
	roleGuid, _ := resp["guid"].(string)
	if roleGuid == "" {
		t.Fatalf("role guid missing: %v", resp)
	}
	child := &entity.User{Guid: "qa-user-child", Username: "qa-child",
		Email: "qa-child@example.com", Status: 1, CreatedAt: seed.Now, UpdatedAt: seed.Now}
	if err := as.DB.Create(child).Error; err != nil {
		t.Fatalf("seed child user: %v", err)
	}
	if err := as.DB.Create(&entity.UserRoleAssignment{Guid: "qa-asg-child",
		UserGuid: child.Guid, RoleGuid: roleGuid, ScopeType: entity.ScopeTypeGlobal,
		CreatedAt: seed.Now, UpdatedAt: seed.Now}).Error; err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	hdr := authHeader(seedToken(t, as, child))
	editBody := map[string]any{"note": "qa-note"}

	// 基线：父+子齐全 → devices.edit 放行。
	status, _, raw = doJSON(t, client, http.MethodPatch,
		as.TS.URL+"/api/devices/"+seed.PeerB.UUID, editBody, hdr)
	if status != http.StatusOK {
		t.Fatalf("baseline edit = %d (%s), want 200", status, raw)
	}

	// 移除父码 devices.view（直写 DB，模拟 API 写路径之外的脏数据）。
	if err := as.DB.Where("roleGuid = ? AND permissionCode = ?", roleGuid, rbac.CodeDevicesView).
		Delete(&entity.RolePermission{}).Error; err != nil {
		t.Fatalf("revoke parent: %v", err)
	}
	status, parsed, _ := doJSON(t, client, http.MethodPatch,
		as.TS.URL+"/api/devices/"+seed.PeerB.UUID, editBody, hdr)
	assertEnvelope(t, status, parsed, http.StatusForbidden, rbac.MsgAccessDenied)

	// 补回父码 → 子码立即恢复可用。
	if err := as.DB.Create(&entity.RolePermission{RoleGuid: roleGuid,
		PermissionCode: rbac.CodeDevicesView}).Error; err != nil {
		t.Fatalf("restore parent: %v", err)
	}
	status, _, raw = doJSON(t, client, http.MethodPatch,
		as.TS.URL+"/api/devices/"+seed.PeerB.UUID, editBody, hdr)
	if status != http.StatusOK {
		t.Errorf("restored edit = %d (%s), want 200", status, raw)
	}
}

// TestQAScopeCrossGroupSingleTarget403 device_group scope 单目标资源级
// 复核矩阵：跨组设备、未分组设备一律 403 固定文案；组内设备放行。
// 覆盖 PATCH note / DELETE / PATCH status 三端点（区别于工程师既有
// disconnect 与批量混合用例）。
func TestQAScopeCrossGroupSingleTarget403(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	grantQA(t, as, seed.RoleDev.Guid, rbac.CodeDevicesEdit)
	grantQA(t, as, seed.RoleDev.Guid, rbac.CodeDevicesDelete)
	grantQA(t, as, seed.RoleDev.Guid, rbac.CodeDevicesStatus)
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	// 跨组（PeerC @ DG2）：PATCH note。
	status, parsed, _ := doJSON(t, client, http.MethodPatch,
		as.TS.URL+"/api/devices/"+seed.PeerC.UUID,
		map[string]any{"note": "x"}, scoped)
	assertEnvelope(t, status, parsed, http.StatusForbidden, rbac.MsgDeviceNotInScope)

	// 未分组（PeerB）：对 scoped 一律拒绝（设计 §1.1② 决策算法 4）。
	status, parsed, _ = doJSON(t, client, http.MethodPatch,
		as.TS.URL+"/api/devices/"+seed.PeerB.UUID,
		map[string]any{"note": "x"}, scoped)
	assertEnvelope(t, status, parsed, http.StatusForbidden, rbac.MsgDeviceNotInScope)

	// DELETE 跨组。
	status, parsed, _ = doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/devices/"+seed.PeerC.UUID, nil, scoped)
	assertEnvelope(t, status, parsed, http.StatusForbidden, rbac.MsgDeviceNotInScope)

	// status 单目标跨组。
	status, parsed, _ = doJSON(t, client, http.MethodPatch, as.TS.URL+"/api/devices/status",
		map[string]any{"guids": []string{seed.PeerC.UUID}, "status": "disabled"}, scoped)
	assertEnvelope(t, status, parsed, http.StatusForbidden, rbac.MsgBatchUnauthorized)

	// 组内对照（PeerA @ DG1）：PATCH note 放行。
	status, _, raw := doJSON(t, client, http.MethodPatch,
		as.TS.URL+"/api/devices/"+seed.PeerA.UUID,
		map[string]any{"note": "in-scope"}, scoped)
	if status != http.StatusOK {
		t.Errorf("in-scope patch = %d (%s), want 200", status, raw)
	}

	// 数据完整性：403 后目标设备未被改动。
	var p entity.Peer
	if err := as.DB.Where("uuid = ?", seed.PeerC.UUID).First(&p).Error; err != nil {
		t.Fatalf("load peer c: %v", err)
	}
	if p.Status != entity.PeerStatusActive {
		t.Errorf("PeerC status = %d, want unchanged after 403", p.Status)
	}
}
