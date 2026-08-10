// rbac_contract_test.go RBAC 域契约用例：11 端点以 openapi.yaml 为准绳
// 双向校验（kin-openapi openapi3filter）。锁定：目录 {data} 无 total 与
// requires 恒为数组、生效权限 scopes 形态、roles 写路径 super
// administrator 路线文案、uuid v4 400（kin-openapi 未内建 uuid 校验器，
// 服务层防线独立生效）、重名 409、权限码 400 族、取消保护 confirm
// 门槛、protection-impact、用户角色三端点（{data, effective_scope}
// 形态、防护链、eligibility reason_code 全分支）。
package contract

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// newRbacServer RBAC 域契约服务器（复用 M2 全栈基建：真实路由 + 内存库
// + SeedM2，禁 per-IP 限流）。
func newRbacServer(t *testing.T) (*contractServer, *apptest.AppServer, *testutil.SeedM2Data) {
	t.Helper()
	return newGroupStrategyServer(t)
}

// TestContractPermissionsCatalog 目录只读（roles.view）：{data:[...]}
// 无 total、定义顺序、system_only 标记、requires 依赖链、恒为数组
// （nil 序列化为 null 违反 array 契约）。
func TestContractPermissionsCatalog(t *testing.T) {
	cs, as, seed := newRbacServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))

	raw := cs.get(t, "/api/permissions", admin, 200)
	m := decodeMap(t, raw)
	rows, ok := m["data"].([]any)
	if !ok {
		t.Fatalf("data missing: %v", m)
	}
	if len(rows) != 36 {
		t.Fatalf("catalog size = %d, want 36（33 可分配 + 3 system_only）", len(rows))
	}
	first := rows[0].(map[string]any)
	if first["code"] != "users.view" {
		t.Errorf("catalog[0] = %v, want users.view（定义顺序）", first["code"])
	}
	for _, key := range []string{"code", "resource", "action", "name", "scope", "assignable", "system_only", "requires"} {
		if _, has := first[key]; !has {
			t.Errorf("PermissionDefinition.%s missing", key)
		}
	}
	if reqs, ok := first["requires"].([]any); !ok || len(reqs) != 0 {
		t.Errorf("users.view.requires = %v, want []（恒为数组）", first["requires"])
	}
	byCode := map[string]map[string]any{}
	for _, r := range rows {
		row := r.(map[string]any)
		byCode[row["code"].(string)] = row
	}
	if got := byCode["roles.create"]; got["system_only"] != true || got["assignable"] != false {
		t.Errorf("roles.create = system_only %v assignable %v, want true/false", got["system_only"], got["assignable"])
	}
	if got := byCode["devices.view"]; got["scope"] != "device_group" {
		t.Errorf("devices.view.scope = %v, want device_group", got["scope"])
	}
	reqs := byCode["strategies.assign"]["requires"].([]any)
	if len(reqs) != 2 || reqs[0] != "strategies.view" || reqs[1] != "users.view" {
		t.Errorf("strategies.assign.requires = %v, want [strategies.view users.view]", reqs)
	}

	// scoped 未持 roles.view → 403 Access denied。
	raw = cs.get(t, "/api/permissions", scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAccessDenied {
		t.Errorf("no-perm message = %v, want %q", msg, rbac.MsgAccessDenied)
	}
}

// TestContractPermissionsMe 生效权限（Auth）：admin 全量可分配码
// （scopes.global=33、device_group={}）；scoped 依赖过滤后码集 +
// 设备组映射（组内码字典序）；global 空数组非 null；被禁用户 401。
func TestContractPermissionsMe(t *testing.T) {
	cs, as, seed := newRbacServer(t)

	raw := cs.get(t, "/api/permissions/me", bearer(m2Token(t, as, seed.Admin)), 200)
	m := decodeMap(t, raw)
	perms := m["permissions"].([]any)
	if len(perms) != 33 {
		t.Errorf("admin permissions = %d, want 33（排除 system_only）", len(perms))
	}
	scopes := m["scopes"].(map[string]any)
	if g := scopes["global"].([]any); len(g) != 33 {
		t.Errorf("admin scopes.global = %d, want 33", len(g))
	}
	if dg, ok := scopes["device_group"].(map[string]any); !ok || len(dg) != 0 {
		t.Errorf("admin scopes.device_group = %v, want {}", scopes["device_group"])
	}

	// scoped：devices.view+disconnect @ DG1（依赖过滤后目录顺序）。
	raw = cs.get(t, "/api/permissions/me", bearer(m2Token(t, as, seed.Scoped)), 200)
	m = decodeMap(t, raw)
	perms = m["permissions"].([]any)
	if len(perms) != 2 || perms[0] != "devices.view" || perms[1] != "devices.disconnect" {
		t.Errorf("scoped permissions = %v, want [devices.view devices.disconnect]", perms)
	}
	scopes = m["scopes"].(map[string]any)
	if g := scopes["global"].([]any); len(g) != 0 {
		t.Errorf("scoped scopes.global = %v, want []", g)
	}
	dg := scopes["device_group"].(map[string]any)
	codes := dg[seed.DG1.Guid].([]any)
	if len(codes) != 2 || codes[0] != "devices.disconnect" || codes[1] != "devices.view" {
		t.Errorf("scoped device_group codes = %v, want [devices.disconnect devices.view]（字典序）", codes)
	}

	// 被禁用户 → 401 固定文案（Auth 实时复核）。
	raw = cs.get(t, "/api/permissions/me", bearer(m2Token(t, as, seed.Disabled)), 401)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAccountDisabled {
		t.Errorf("disabled message = %v, want %q", msg, rbac.MsgAccountDisabled)
	}
}

// TestContractRolesListAndCreate 列表（roles.view）与创建（super
// administrator）：name ASC、6 必需键、name LIKE、roles 路线 403 文案、
// 重名 409、system_only/未知码 400、requires 缺失 400（目录顺序逗号
// 空格连接）、请求体契约双防线。
func TestContractRolesListAndCreate(t *testing.T) {
	cs, as, seed := newRbacServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))

	raw := cs.get(t, "/api/roles", admin, 200)
	m := decodeMap(t, raw)
	rows := m["data"].([]any)
	if len(rows) != 3 || m["total"].(float64) != 3 {
		t.Fatalf("roles = %d/%v, want 3/3", len(rows), m["total"])
	}
	first := rows[0].(map[string]any)
	if first["name"] != "device-operator" {
		t.Errorf("first role = %v, want device-operator（name ASC）", first["name"])
	}
	for _, key := range []string{"guid", "name", "note", "protected_account", "created_at", "updated_at"} {
		if _, has := first[key]; !has {
			t.Errorf("RoleView.%s missing", key)
		}
	}
	raw = cs.get(t, "/api/roles?name=pro", admin, 200)
	if rows := decodeMap(t, raw)["data"].([]any); len(rows) != 1 {
		t.Errorf("name LIKE = %d rows, want 1", len(rows))
	}

	// scoped 未持 roles.view → 403 Access denied；
	// 写路径未持超管 → roles 路线文案（与 device-groups 路线区分）。
	raw = cs.get(t, "/api/roles", scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAccessDenied {
		t.Errorf("no-perm message = %v, want %q", msg, rbac.MsgAccessDenied)
	}
	raw = cs.post(t, "/api/roles", map[string]any{"name": "X"}, scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgSuperAdminRequired {
		t.Errorf("super admin message = %v, want %q", msg, rbac.MsgSuperAdminRequired)
	}

	// 创建：合法权限码集。
	raw = cs.post(t, "/api/roles", map[string]any{
		"name": "contract-role", "note": "n",
		"permissions": []string{"devices.view", "devices.disconnect"},
	}, admin, 200)
	m = decodeMap(t, raw)
	created, ok := m["guid"].(string)
	if !ok || created == "" {
		t.Fatalf("created guid = %v", m["guid"])
	}
	if m["name"] != "contract-role" || m["note"] != "n" || m["protected_account"] != false {
		t.Errorf("created view = %v", m)
	}

	// 重名 409（与设备组/策略 400 区分）。
	raw = cs.post(t, "/api/roles", map[string]any{"name": "device-operator"}, admin, 409)
	if msg := decodeMap(t, raw)["message"]; msg != "Role name already exists" {
		t.Errorf("dup message = %v, want Role name already exists", msg)
	}
	// system_only / 未知码 → 400。
	raw = cs.post(t, "/api/roles", map[string]any{"name": "Y", "permissions": []string{"roles.create"}}, admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Permission code cannot be assigned: roles.create" {
		t.Errorf("system_only message = %v", msg)
	}
	raw = cs.post(t, "/api/roles", map[string]any{"name": "Y", "permissions": []string{"no.such"}}, admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Permission code cannot be assigned: no.such" {
		t.Errorf("unknown message = %v", msg)
	}
	// requires 缺失 → 400（目录顺序去重逗号空格连接）。
	raw = cs.post(t, "/api/roles", map[string]any{"name": "Y", "permissions": []string{"devices.disconnect"}}, admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Missing permission dependencies: devices.view" {
		t.Errorf("missing deps message = %v", msg)
	}
	raw = cs.post(t, "/api/roles", map[string]any{"name": "Y", "permissions": []string{"strategies.assign"}}, admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Missing permission dependencies: strategies.view, users.view" {
		t.Errorf("multi deps message = %v", msg)
	}
	// 请求体契约双防线：未知字段 / 缺 name。
	cs.invalid(t, http.MethodPost, "/api/roles", map[string]any{"name": "Z", "evil": 1}, admin, 400)
	cs.invalid(t, http.MethodPost, "/api/roles", map[string]any{"note": "no name"}, admin, 400)

	_ = created
}

// TestContractRolesDetailUpdateDelete 详情（uuid v4 门槛 + permissions
// 目录顺序 + 零权限恒 []）、protection-impact、更新（三态 + confirm
// 门槛 + 改名重名 409）、删除（级联删净 + 空对象响应）。
func TestContractRolesDetailUpdateDelete(t *testing.T) {
	cs, as, seed := newRbacServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	raw := cs.post(t, "/api/roles", map[string]any{
		"name": "impacted", "permissions": []string{"devices.view", "devices.disconnect"},
	}, admin, 200)
	roleGuid := decodeMap(t, raw)["guid"].(string)

	// 挂一个用户（直插指派 + 组关联），支撑 impact 计数与删除级联。
	asg := &entity.UserRoleAssignment{
		Guid: uuid.NewString(), UserGuid: seed.Scoped.Guid, RoleGuid: roleGuid,
		ScopeType: entity.ScopeTypeDeviceGroup, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := as.DB.Create(asg).Error; err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	if err := as.DB.Create(&entity.UserRoleAssignmentDeviceGroup{
		AssignmentGuid: asg.Guid, DeviceGroupGuid: seed.DG1.Guid,
	}).Error; err != nil {
		t.Fatalf("seed assignment group: %v", err)
	}

	// 非法 uuid → 400（服务层校验，固定文案）。
	raw = cs.get(t, "/api/roles/seed-role-dev", admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Validation failed (uuid is expected)" {
		t.Errorf("invalid uuid message = %v", msg)
	}
	// 合法 uuid 不存在 → 404 "Role not found"。
	raw = cs.get(t, "/api/roles/"+uuid.NewString(), admin, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "Role not found" {
		t.Errorf("404 message = %v, want Role not found", msg)
	}
	// 详情：permissions 目录顺序。
	raw = cs.get(t, "/api/roles/"+roleGuid, admin, 200)
	m := decodeMap(t, raw)
	perms := m["permissions"].([]any)
	if len(perms) != 2 || perms[0] != "devices.view" || perms[1] != "devices.disconnect" {
		t.Errorf("detail permissions = %v, want [devices.view devices.disconnect]", perms)
	}

	// protection-impact：挂在该角色上的用户数（无 total）。
	raw = cs.get(t, "/api/roles/"+roleGuid+"/protection-impact", admin, 200)
	if got := decodeMap(t, raw)["affected_member_count"]; got != float64(1) {
		t.Errorf("affected_member_count = %v, want 1", got)
	}
	cs.get(t, "/api/roles/"+uuid.NewString()+"/protection-impact", admin, 404)

	// 更新：改名（permissions 未提供保持原值）。
	raw = cs.patch(t, "/api/roles/"+roleGuid, map[string]any{"name": "impacted-2"}, admin, 200)
	if m = decodeMap(t, raw); m["name"] != "impacted-2" {
		t.Errorf("renamed = %v", m["name"])
	}
	// 改名撞已有角色 → 409；404；请求体未知字段双防线。
	cs.patch(t, "/api/roles/"+roleGuid, map[string]any{"name": "device-operator"}, admin, 409)
	cs.patch(t, "/api/roles/"+uuid.NewString(), map[string]any{"name": "Z"}, admin, 404)
	cs.invalid(t, http.MethodPatch, "/api/roles/"+roleGuid, map[string]any{"evil": 1}, admin, 400)

	// 创建保护角色 → 取消保护须显式 confirm。
	raw = cs.post(t, "/api/roles", map[string]any{"name": "prot", "protected_account": true}, admin, 200)
	protGuid := decodeMap(t, raw)["guid"].(string)
	raw = cs.patch(t, "/api/roles/"+protGuid, map[string]any{"protected_account": false}, admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Confirmation required to remove protected account" {
		t.Errorf("confirm message = %v", msg)
	}
	raw = cs.patch(t, "/api/roles/"+protGuid, map[string]any{
		"protected_account": false, "confirm_protected_account_change": true,
	}, admin, 200)
	if m = decodeMap(t, raw); m["protected_account"] != false {
		t.Errorf("unprotected = %v", m)
	}

	// 删除：空对象；级联删净指派；复删 404。
	raw = cs.delete(t, "/api/roles/"+roleGuid, admin, 200)
	if m := decodeMap(t, raw); len(m) != 0 {
		t.Errorf("delete response = %v, want empty object", m)
	}
	var count int64
	if err := as.DB.Model(&entity.UserRoleAssignment{}).
		Where("roleGuid = ?", roleGuid).Count(&count).Error; err != nil {
		t.Fatalf("count assignments: %v", err)
	}
	if count != 0 {
		t.Errorf("assignments after delete = %d, want 0（事务级联）", count)
	}
	cs.delete(t, "/api/roles/"+roleGuid, admin, 404)
}

// TestContractUserRolesReplace 用户角色三端点（roles.assign）：
// {data, effective_scope} 形态、自改 403、404 族、scope 形态 400 族、
// 重复角色 400、全量替换与清空。
func TestContractUserRolesReplace(t *testing.T) {
	cs, as, seed := newRbacServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))
	scopedGUID := seed.Scoped.Guid
	put := func(path string, body any, headers map[string]string, status int) []byte {
		return cs.raw(t, http.MethodPut, path, body, headers, status)
	}

	// GET：scoped 现有指派（seed：device-operator @ DG1）。
	raw := cs.get(t, "/api/users/"+scopedGUID+"/roles", admin, 200)
	m := decodeMap(t, raw)
	rows := m["data"].([]any)
	if len(rows) != 1 {
		t.Fatalf("data = %v", m)
	}
	row := rows[0].(map[string]any)
	for _, key := range []string{"role_guid", "role_name", "scope_type", "device_group_guids"} {
		if _, has := row[key]; !has {
			t.Errorf("AssignmentDto.%s missing", key)
		}
	}
	if row["role_guid"] != seed.RoleDev.Guid || row["role_name"] != "device-operator" ||
		row["scope_type"] != "device_group" {
		t.Errorf("assignment = %v", row)
	}
	if g := row["device_group_guids"].([]any); len(g) != 1 || g[0] != seed.DG1.Guid {
		t.Errorf("device_group_guids = %v", row["device_group_guids"])
	}
	if m["effective_scope"] != "device_group" {
		t.Errorf("effective_scope = %v, want device_group", m["effective_scope"])
	}
	// 无指派用户 → none + 空数组；目标不存在 → 404。
	raw = cs.get(t, "/api/users/"+seed.Disabled.Guid+"/roles", admin, 200)
	if m = decodeMap(t, raw); m["effective_scope"] != "none" || len(m["data"].([]any)) != 0 {
		t.Errorf("none user = %v", m)
	}
	raw = cs.get(t, "/api/users/no-such-user/roles", admin, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "User does not exist" {
		t.Errorf("404 message = %v, want User does not exist", msg)
	}

	// PUT 自改 → 403（自改判定最先）。
	raw = put("/api/users/"+seed.Admin.Guid+"/roles", map[string]any{"assignments": []any{}}, admin, 403)
	if msg := decodeMap(t, raw)["message"]; msg != "You cannot modify your own roles" {
		t.Errorf("self message = %v, want You cannot modify your own roles", msg)
	}

	// PUT 角色不存在 → 404；重复角色 → 400。
	put("/api/users/"+scopedGUID+"/roles", map[string]any{
		"assignments": []map[string]any{{"role_guid": "no-such-role", "scope_type": "global"}},
	}, admin, 404)
	raw = put("/api/users/"+scopedGUID+"/roles", map[string]any{
		"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "global"},
			{"role_guid": seed.RoleDev.Guid, "scope_type": "device_group", "device_group_guids": []string{seed.DG1.Guid}},
		},
	}, admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Duplicate role assignment" {
		t.Errorf("dup message = %v, want Duplicate role assignment", msg)
	}

	// scope 形态 400/404 族。
	raw = put("/api/users/"+scopedGUID+"/roles", map[string]any{
		"assignments": []map[string]any{{"role_guid": seed.RoleDev.Guid, "scope_type": "device_group"}},
	}, admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Device group scope requires at least one device group" {
		t.Errorf("needs group message = %v", msg)
	}
	raw = put("/api/users/"+scopedGUID+"/roles", map[string]any{
		"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "global", "device_group_guids": []string{seed.DG1.Guid}},
		},
	}, admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Global scope must not contain device groups" {
		t.Errorf("global with groups message = %v", msg)
	}
	raw = put("/api/users/"+scopedGUID+"/roles", map[string]any{
		"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "device_group", "device_group_guids": []string{"ghost-dg"}},
		},
	}, admin, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "Device group does not exist" {
		t.Errorf("ghost group message = %v", msg)
	}
	// 混档码角色（devices.view+users.view）device_group 指派 → 400。
	raw = cs.post(t, "/api/roles", map[string]any{
		"name": "mixed", "permissions": []string{"devices.view", "users.view"},
	}, admin, 200)
	mixedGuid := decodeMap(t, raw)["guid"].(string)
	raw = put("/api/users/"+scopedGUID+"/roles", map[string]any{
		"assignments": []map[string]any{
			{"role_guid": mixedGuid, "scope_type": "device_group", "device_group_guids": []string{seed.DG1.Guid}},
		},
	}, admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Device group scope can only contain device-scoped permissions" {
		t.Errorf("mixed codes message = %v", msg)
	}

	// PUT 全量替换：device_group + global 混合 → 任一 global 即 global。
	raw = put("/api/users/"+scopedGUID+"/roles", map[string]any{
		"assignments": []map[string]any{
			{"role_guid": seed.RoleDev.Guid, "scope_type": "device_group", "device_group_guids": []string{seed.DG1.Guid}},
			{"role_guid": seed.RoleGlobal.Guid, "scope_type": "global"},
		},
	}, admin, 200)
	m = decodeMap(t, raw)
	if m["effective_scope"] != "global" {
		t.Errorf("effective_scope = %v, want global（任一 global 即 global）", m["effective_scope"])
	}
	rows = m["data"].([]any)
	if len(rows) != 2 {
		t.Fatalf("replaced data = %v", m["data"])
	}
	byRole := map[string]map[string]any{}
	for _, r := range rows {
		rm := r.(map[string]any)
		byRole[rm["role_guid"].(string)] = rm
	}
	if g := byRole[seed.RoleDev.Guid]["device_group_guids"].([]any); len(g) != 1 || g[0] != seed.DG1.Guid {
		t.Errorf("replaced groups = %v", byRole[seed.RoleDev.Guid])
	}
	if g := byRole[seed.RoleGlobal.Guid]["device_group_guids"].([]any); len(g) != 0 {
		t.Errorf("global assignment groups = %v, want []", byRole[seed.RoleGlobal.Guid])
	}

	// 清空替换 → none + 空数组。
	raw = put("/api/users/"+scopedGUID+"/roles", map[string]any{"assignments": []map[string]any{}}, admin, 200)
	m = decodeMap(t, raw)
	if m["effective_scope"] != "none" || len(m["data"].([]any)) != 0 {
		t.Errorf("cleared = %v", m)
	}

	// 请求体契约双防线：assignments 元素未知字段。
	cs.invalid(t, http.MethodPut, "/api/users/"+scopedGUID+"/roles", map[string]any{
		"assignments": []map[string]any{{"role_guid": "x", "scope_type": "global", "evil": 1}},
	}, admin, 400)
}

// TestContractUserRoleEligibility 资格矩阵 reason_code 全分支：
// eligible / self_target / target_protected / protected_role /
// super_admin_target（第二管理员经临时解除单管理员约束构造）。
func TestContractUserRoleEligibility(t *testing.T) {
	cs, as, seed := newRbacServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	byCode := func(raw []byte) map[string]map[string]any {
		out := map[string]map[string]any{}
		rows := decodeMap(t, raw)["data"].([]any)
		for _, r := range rows {
			rm := r.(map[string]any)
			for _, key := range []string{"role_guid", "role_name", "protected_account", "eligible", "reason_code"} {
				if _, has := rm[key]; !has {
					t.Fatalf("EligibilityRow.%s missing: %v", key, rm)
				}
			}
			out[rm["role_guid"].(string)] = rm
		}
		return out
	}

	// eligible：admin → scoped（三角色全部可派，含保护角色——超管不受限）。
	rows := byCode(cs.get(t, "/api/users/"+seed.Scoped.Guid+"/roles/eligibility", admin, 200))
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	for guid, rm := range rows {
		if rm["eligible"] != true || rm["reason_code"] != "eligible" {
			t.Errorf("row %s = %v/%v, want true/eligible", guid, rm["eligible"], rm["reason_code"])
		}
	}

	// self_target：admin 查自己 → 全行 false/self_target。
	rows = byCode(cs.get(t, "/api/users/"+seed.Admin.Guid+"/roles/eligibility", admin, 200))
	for guid, rm := range rows {
		if rm["eligible"] != false || rm["reason_code"] != "self_target" {
			t.Errorf("row %s = %v/%v, want false/self_target", guid, rm["eligible"], rm["reason_code"])
		}
	}

	// 非超管操作者（assigner）：users.view + roles.view + roles.assign
	// （roles.assign 依赖须全给足，经生效码过滤后才可见）。
	assigner := &entity.User{Guid: "qa-user-assigner", Username: "assigner", Email: "assigner@example.com", Status: 1, CreatedAt: seed.Now, UpdatedAt: seed.Now}
	assignerRole := &entity.Role{Guid: "qa-role-assigner", Name: "assigner-role", CreatedAt: seed.Now, UpdatedAt: seed.Now}
	for _, r := range []any{
		assigner, assignerRole,
		&entity.RolePermission{RoleGuid: assignerRole.Guid, PermissionCode: rbac.CodeUsersView},
		&entity.RolePermission{RoleGuid: assignerRole.Guid, PermissionCode: rbac.CodeRolesView},
		&entity.RolePermission{RoleGuid: assignerRole.Guid, PermissionCode: rbac.CodeRolesAssign},
		&entity.UserRoleAssignment{Guid: "qa-asg-assigner", UserGuid: assigner.Guid, RoleGuid: assignerRole.Guid, ScopeType: entity.ScopeTypeGlobal, CreatedAt: seed.Now, UpdatedAt: seed.Now},
	} {
		if err := as.DB.Create(r).Error; err != nil {
			t.Fatalf("seed %T: %v", r, err)
		}
	}
	assignerHdr := bearer(m2Token(t, as, assigner))

	// target_protected：目标为保护账号（owner 挂保护角色）→ 全行拒绝。
	rows = byCode(cs.get(t, "/api/users/"+seed.Owner.Guid+"/roles/eligibility", assignerHdr, 200))
	for guid, rm := range rows {
		if rm["eligible"] != false || rm["reason_code"] != "target_protected" {
			t.Errorf("row %s = %v/%v, want false/target_protected", guid, rm["eligible"], rm["reason_code"])
		}
	}

	// protected_role：目标非保护 → 仅保护角色行拒绝。
	rows = byCode(cs.get(t, "/api/users/"+seed.Scoped.Guid+"/roles/eligibility", assignerHdr, 200))
	for guid, rm := range rows {
		wantReason, wantEligible := "eligible", true
		if guid == seed.RoleProt.Guid {
			wantReason, wantEligible = "protected_role", false
		}
		if rm["eligible"] != wantEligible || rm["reason_code"] != wantReason {
			t.Errorf("row %s = %v/%v, want %v/%v", guid, rm["eligible"], rm["reason_code"], wantEligible, wantReason)
		}
	}
	cs.get(t, "/api/users/no-such-user/roles/eligibility", admin, 404)

	// super_admin_target：目标为第二管理员且角色非保护（解除单管理员
	// 约束构造第二超管；保护角色行仍可派 → eligible）。
	if err := as.DB.Exec("DROP INDEX IF EXISTS UQ_users_single_owner").Error; err != nil {
		t.Fatalf("drop single owner index: %v", err)
	}
	second := &entity.User{Guid: "qa-user-admin-2", Username: "admin-two", Email: "admin-two@example.com", Status: 1, IsAdmin: true, CreatedAt: seed.Now, UpdatedAt: seed.Now}
	if err := as.DB.Create(second).Error; err != nil {
		t.Fatalf("seed second admin: %v", err)
	}
	rows = byCode(cs.get(t, "/api/users/"+second.Guid+"/roles/eligibility", admin, 200))
	for guid, rm := range rows {
		if guid == seed.RoleProt.Guid {
			if rm["eligible"] != true {
				t.Errorf("protected role to admin target = %v, want eligible（超管可派保护角色给超管）", rm["eligible"])
			}
			continue
		}
		if rm["eligible"] != false || rm["reason_code"] != "super_admin_target" {
			t.Errorf("row %s = %v/%v, want false/super_admin_target", guid, rm["eligible"], rm["reason_code"])
		}
	}
}
