// m2_rbac_security_test.go RBAC/用户组域独立安全用例（设计 §2
// qa/m2_rbac_security_test.go）：越权矩阵——无 roles.assign 路由拒绝
// （+denied 审计）、被禁用户 401、自改角色拒绝、非超管派 global 指派
// 拒绝、组越界拒绝、保护账号复核、超管目标仅保护角色、scope 形态
// 400 族、成员移动保护账号复核、roles 写路径与 device-groups 路线
// 双文案差异。
//
// 与 contract 包的分工：contract 锁 openapi 请求/响应形状；本包聚焦
// 服务端行为语义与安全反例，不做契约校验（独立再验一遍核心语义）。
package qa

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// TestM2RbacRouteDenialAudited 无 roles.assign 的 scoped 操作者 →
// 路由层 403 Access denied + denied 审计落库；被禁用户 401（JWT 有效、
// 实时状态复核拒绝）。
func TestM2RbacRouteDenialAudited(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	status, _, raw := doJSON(t, client, http.MethodPut,
		as.TS.URL+"/api/users/"+seed.Scoped.Guid+"/roles",
		map[string]any{"assignments": []any{}}, scoped)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", status, raw)
	}
	if !strings.Contains(string(raw), rbac.MsgAccessDenied) {
		t.Errorf("message = %s, want %q", raw, rbac.MsgAccessDenied)
	}

	// denied 审计落库（红线：拒绝决策写 console_audits）。
	var audits []entity.ConsoleAudit
	if err := as.DB.Where("actorUserGuid = ? AND result = ? AND action = ?",
		seed.Scoped.Guid, rbac.AuditResultDenied, rbac.CodeRolesAssign).
		Find(&audits).Error; err != nil {
		t.Fatalf("query audits: %v", err)
	}
	if len(audits) == 0 {
		t.Fatal("denied audit must be recorded for roles.assign")
	}

	// 被禁用户访问 roles 列表 → 401 固定文案。
	disabled := authHeader(seedToken(t, as, seed.Disabled))
	status, _, raw = doJSON(t, client, http.MethodGet, as.TS.URL+"/api/roles", nil, disabled)
	if status != http.StatusUnauthorized {
		t.Fatalf("disabled status = %d, want 401 (%s)", status, raw)
	}
	if !strings.Contains(string(raw), rbac.MsgAccountDisabled) {
		t.Errorf("disabled message = %s, want %q", raw, rbac.MsgAccountDisabled)
	}
}

// TestM2RbacReplaceProtectionChain 替换指派防护链语义：自改 403、
// 非超管派 global 指派 403（提权）、组越界 403、范围内放行 200、
// 保护账号 403、超管目标仅保护角色（第二管理员经临时解除单管理员
// 约束构造）。
func TestM2RbacReplaceProtectionChain(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))
	now := seed.Now

	// assigner-global：users.view + roles.view + roles.assign（global）。
	assigner := &entity.User{Guid: "qa-user-assigner", Username: "qa-assigner", Email: "qa-assigner@example.com", Status: 1, CreatedAt: now, UpdatedAt: now}
	assignerRole := &entity.Role{Guid: "qa-role-assigner", Name: "qa-assigner-role", CreatedAt: now, UpdatedAt: now}
	// assigner-scoped：同码集但仅 DG1（组越界用例）。
	scopedAssigner := &entity.User{Guid: "qa-user-assigner-dg", Username: "qa-assigner-dg", Email: "qa-assigner-dg@example.com", Status: 1, CreatedAt: now, UpdatedAt: now}
	asgDG := &entity.UserRoleAssignment{Guid: "qa-asg-assigner-dg", UserGuid: scopedAssigner.Guid, RoleGuid: assignerRole.Guid, ScopeType: entity.ScopeTypeDeviceGroup, CreatedAt: now, UpdatedAt: now}
	for i, row := range []any{
		assigner, assignerRole, scopedAssigner, asgDG,
		&entity.RolePermission{RoleGuid: assignerRole.Guid, PermissionCode: rbac.CodeUsersView},
		&entity.RolePermission{RoleGuid: assignerRole.Guid, PermissionCode: rbac.CodeRolesView},
		&entity.RolePermission{RoleGuid: assignerRole.Guid, PermissionCode: rbac.CodeRolesAssign},
		&entity.UserRoleAssignmentDeviceGroup{AssignmentGuid: asgDG.Guid, DeviceGroupGuid: seed.DG1.Guid},
		&entity.UserRoleAssignment{Guid: "qa-asg-assigner", UserGuid: assigner.Guid, RoleGuid: assignerRole.Guid, ScopeType: entity.ScopeTypeGlobal, CreatedAt: now, UpdatedAt: now},
	} {
		if err := as.DB.Create(row).Error; err != nil {
			t.Fatalf("seed[%d] %T: %v", i, row, err)
		}
	}
	assignerHdr := authHeader(seedToken(t, as, assigner))
	assignerDG := authHeader(seedToken(t, as, scopedAssigner))

	var resp map[string]any

	// 1. 自改拒绝（自改判定最先）。
	status, _, raw := doJSON(t, client, http.MethodPut,
		as.TS.URL+"/api/users/"+seed.Admin.Guid+"/roles",
		map[string]any{"assignments": []any{}}, admin)
	if status != http.StatusForbidden || !strings.Contains(string(raw), rbac.MsgSelfRoleChange) {
		t.Errorf("self change = %d %s, want 403 %q", status, raw, rbac.MsgSelfRoleChange)
	}

	// 2. 非超管派 global 指派 → 403 Access denied（提权防护）。
	status, _, raw = doJSON(t, client, http.MethodPut,
		as.TS.URL+"/api/users/"+seed.Global.Guid+"/roles",
		map[string]any{"assignments": []map[string]any{
			{"role_guid": seed.RoleGlobal.Guid, "scope_type": "global"},
		}}, assignerHdr)
	if status != http.StatusForbidden || !strings.Contains(string(raw), rbac.MsgAccessDenied) {
		t.Errorf("global by non-admin = %d %s, want 403 %q", status, raw, rbac.MsgAccessDenied)
	}

	// 3. 组越界：DG1 授权者派 DG2 → 403 固定文案。
	status, _, raw = doJSON(t, client, http.MethodPut,
		as.TS.URL+"/api/users/"+seed.Scoped.Guid+"/roles",
		map[string]any{"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "device_group", "device_group_guids": []string{seed.DG2.Guid}},
		}}, assignerDG)
	if status != http.StatusForbidden || !strings.Contains(string(raw), rbac.MsgTargetGroupOutside) {
		t.Errorf("outside scope = %d %s, want 403 %q", status, raw, rbac.MsgTargetGroupOutside)
	}
	// DG1 内 → 200（授权范围内可派）。
	status, resp, raw = doJSON(t, client, http.MethodPut,
		as.TS.URL+"/api/users/"+seed.Scoped.Guid+"/roles",
		map[string]any{"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "device_group", "device_group_guids": []string{seed.DG1.Guid}},
		}}, assignerDG)
	if status != http.StatusOK || resp["effective_scope"] != "device_group" {
		t.Errorf("in-scope replace = %d %v (%s)", status, resp, raw)
	}

	// 4. 保护账号复核：owner 挂保护角色，非超管 → 403 固定文案。
	status, _, raw = doJSON(t, client, http.MethodPut,
		as.TS.URL+"/api/users/"+seed.Owner.Guid+"/roles",
		map[string]any{"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "device_group", "device_group_guids": []string{seed.DG1.Guid}},
		}}, assignerHdr)
	if status != http.StatusForbidden || !strings.Contains(string(raw), rbac.MsgProtectedAccount) {
		t.Errorf("protected target = %d %s, want 403 %q", status, raw, rbac.MsgProtectedAccount)
	}

	// 5. 超管目标仅保护角色：常规角色 → 403；保护角色 → 200。
	if err := as.DB.Exec("DROP INDEX IF EXISTS UQ_users_single_owner").Error; err != nil {
		t.Fatalf("drop single owner index: %v", err)
	}
	second := &entity.User{Guid: "qa-user-admin-2", Username: "qa-admin-two", Email: "qa-admin-two@example.com", Status: 1, IsAdmin: true, CreatedAt: now, UpdatedAt: now}
	if err := as.DB.Create(second).Error; err != nil {
		t.Fatalf("seed second admin: %v", err)
	}
	status, _, raw = doJSON(t, client, http.MethodPut,
		as.TS.URL+"/api/users/"+second.Guid+"/roles",
		map[string]any{"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "global"},
		}}, admin)
	if status != http.StatusForbidden || !strings.Contains(string(raw), rbac.MsgSuperAdminRegularRole) {
		t.Errorf("admin target regular role = %d %s, want 403 %q", status, raw, rbac.MsgSuperAdminRegularRole)
	}
	status, resp, raw = doJSON(t, client, http.MethodPut,
		as.TS.URL+"/api/users/"+second.Guid+"/roles",
		map[string]any{"assignments": []map[string]any{
			{"role_guid": seed.RoleProt.Guid, "scope_type": "global"},
		}}, admin)
	if status != http.StatusOK || resp["effective_scope"] != "global" {
		t.Errorf("admin target protected role = %d %v (%s)", status, resp, raw)
	}
}

// TestM2RbacScopeShapeValidation 指派载荷 scope 形态 400 族：重复角色、
// device_group 无组、global 带组、混档码角色组档、幽灵组/幽灵角色 404。
func TestM2RbacScopeShapeValidation(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))
	target := as.TS.URL + "/api/users/" + seed.Global.Guid + "/roles"

	// 重复角色 → 400。
	status, _, raw := doJSON(t, client, http.MethodPut, target, map[string]any{
		"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "global"},
			{"role_guid": seed.RoleDev.Guid, "scope_type": "device_group", "device_group_guids": []string{seed.DG1.Guid}},
		}}, admin)
	if status != http.StatusBadRequest || !strings.Contains(string(raw), "Duplicate role assignment") {
		t.Errorf("dup = %d %s", status, raw)
	}
	// device_group 无组 → 400。
	status, _, raw = doJSON(t, client, http.MethodPut, target, map[string]any{
		"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "device_group"},
		}}, admin)
	if status != http.StatusBadRequest || !strings.Contains(string(raw), "Device group scope requires at least one device group") {
		t.Errorf("needs group = %d %s", status, raw)
	}
	// global 带组 → 400。
	status, _, raw = doJSON(t, client, http.MethodPut, target, map[string]any{
		"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "global", "device_group_guids": []string{seed.DG1.Guid}},
		}}, admin)
	if status != http.StatusBadRequest || !strings.Contains(string(raw), "Global scope must not contain device groups") {
		t.Errorf("global with groups = %d %s", status, raw)
	}
	// 幽灵组 → 404；幽灵角色 → 404。
	status, _, raw = doJSON(t, client, http.MethodPut, target, map[string]any{
		"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "device_group", "device_group_guids": []string{"ghost-dg"}},
		}}, admin)
	if status != http.StatusNotFound || !strings.Contains(string(raw), "Device group does not exist") {
		t.Errorf("ghost group = %d %s", status, raw)
	}
	status, _, raw = doJSON(t, client, http.MethodPut, target, map[string]any{
		"assignments": []map[string]any{
			{"role_guid": "no-such-role", "scope_type": "global"},
		}}, admin)
	if status != http.StatusNotFound || !strings.Contains(string(raw), "Role not found") {
		t.Errorf("ghost role = %d %s", status, raw)
	}

	// 混档码角色（devices.view+users.view）device_group 指派 → 400
	// （组档仅限 device_group 档六码）。
	mixed := &entity.Role{Guid: "qa-role-mixed", Name: "qa-mixed", CreatedAt: seed.Now, UpdatedAt: seed.Now}
	if err := as.DB.Create(mixed).Error; err != nil {
		t.Fatalf("seed mixed role: %v", err)
	}
	grantQA(t, as, mixed.Guid, rbac.CodeDevicesView)
	grantQA(t, as, mixed.Guid, rbac.CodeUsersView)
	status, _, raw = doJSON(t, client, http.MethodPut, target, map[string]any{
		"assignments": []map[string]any{
			{"role_guid": mixed.Guid, "scope_type": "device_group", "device_group_guids": []string{seed.DG1.Guid}},
		}}, admin)
	if status != http.StatusBadRequest || !strings.Contains(string(raw), "Device group scope can only contain device-scoped permissions") {
		t.Errorf("mixed codes = %d %s", status, raw)
	}
}

// TestM2UserGroupMoveProtection 成员移动越权矩阵：非超管移动保护账号
// 403、批量幽灵 404 整体拒绝、超管移动保护账号放行。
func TestM2UserGroupMoveProtection(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))
	now := seed.Now

	// mover：user_groups.view + user_groups.membership（global）。
	mover := &entity.User{Guid: "qa-user-mover", Username: "qa-mover", Email: "qa-mover@example.com", Status: 1, CreatedAt: now, UpdatedAt: now}
	moverRole := &entity.Role{Guid: "qa-role-mover", Name: "qa-mover-role", CreatedAt: now, UpdatedAt: now}
	for i, row := range []any{
		mover, moverRole,
		&entity.RolePermission{RoleGuid: moverRole.Guid, PermissionCode: rbac.CodeUserGroupsView},
		&entity.RolePermission{RoleGuid: moverRole.Guid, PermissionCode: rbac.CodeUserGroupsMembership},
		&entity.UserRoleAssignment{Guid: "qa-asg-mover", UserGuid: mover.Guid, RoleGuid: moverRole.Guid, ScopeType: entity.ScopeTypeGlobal, CreatedAt: now, UpdatedAt: now},
	} {
		if err := as.DB.Create(row).Error; err != nil {
			t.Fatalf("seed[%d] %T: %v", i, row, err)
		}
	}
	moverHdr := authHeader(seedToken(t, as, mover))

	// Default 组 guid（database.Seed 建立）。
	var defGroup entity.UserGroup
	if err := as.DB.Where("isDefault = ?", true).First(&defGroup).Error; err != nil {
		t.Fatalf("default group: %v", err)
	}

	// 保护账号（owner 挂保护角色）非超管移动 → 403 固定文案。
	status, _, raw := doJSON(t, client, http.MethodPost,
		as.TS.URL+"/api/user-groups/"+defGroup.Guid+"/users",
		map[string]any{"user_guids": []string{seed.Owner.Guid}}, moverHdr)
	if status != http.StatusForbidden || !strings.Contains(string(raw), rbac.MsgProtectedAccount) {
		t.Errorf("protected move = %d %s, want 403 %q", status, raw, rbac.MsgProtectedAccount)
	}

	// 批量幽灵 → 404 复数文案。
	status, _, raw = doJSON(t, client, http.MethodPost,
		as.TS.URL+"/api/user-groups/"+defGroup.Guid+"/users",
		map[string]any{"user_guids": []string{seed.Disabled.Guid, "ghost-user"}}, moverHdr)
	if status != http.StatusNotFound || !strings.Contains(string(raw), "One or more users do not exist") {
		t.Errorf("ghost move = %d %s, want 404 One or more users do not exist", status, raw)
	}

	// 超管移动保护账号 → 200 moved_user_count=1。
	status, resp, _ := doJSON(t, client, http.MethodPost,
		as.TS.URL+"/api/user-groups/"+defGroup.Guid+"/users",
		map[string]any{"user_guids": []string{seed.Owner.Guid}}, admin)
	if status != http.StatusOK || resp["moved_user_count"] != float64(1) {
		t.Errorf("admin move protected = %d %v", status, resp)
	}
}

// TestM2RbacSuperAdminWriteRoute roles 写路径 super administrator 路线
// 文案（与 device-groups 路线 AdminGuard 文案逐字节区分）。
func TestM2RbacSuperAdminWriteRoute(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/roles"},
		{http.MethodPatch, "/api/roles/00000000-0000-4000-8000-000000000001"},
		{http.MethodDelete, "/api/roles/00000000-0000-4000-8000-000000000001"},
		{http.MethodGet, "/api/roles/00000000-0000-4000-8000-000000000001/protection-impact"},
	} {
		var body any
		if tc.method == http.MethodPost {
			body = map[string]any{"name": "X"}
		}
		status, _, raw := doJSON(t, client, tc.method, as.TS.URL+tc.path, body, scoped)
		if status != http.StatusForbidden || !strings.Contains(string(raw), rbac.MsgSuperAdminRequired) {
			t.Errorf("%s %s = %d %s, want 403 %q", tc.method, tc.path, status, raw, rbac.MsgSuperAdminRequired)
		}
	}

	// device-groups 路线文案（AdminGuard，双文案差异锁定）。
	status, _, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/device-groups", nil, scoped)
	if status != http.StatusForbidden || !strings.Contains(string(raw), rbac.MsgAdminGuardRequired) {
		t.Errorf("admin guard = %d %s, want 403 %q", status, raw, rbac.MsgAdminGuardRequired)
	}
}
