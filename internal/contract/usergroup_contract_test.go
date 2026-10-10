// usergroup_contract_test.go 用户组域契约用例：6 端点以 openapi.yaml
// 为准绳双向校验。锁定：UserGroupView 5 键与 user_count 批量计数、
// 重名 409（大小写不敏感，与设备组/策略 400 区分）、默认组禁删 400、
// 删除成员回落默认组（moved_user_count + deleted_rule_count 恒 0）、
// 成员 search LIKE（username/email）、move 命中计数与批量 404 整体拒绝。
package contract

import (
	"net/http"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// TestContractUserGroupsListCreateUpdate 列表/创建/更新（user_groups
// view/create/edit 分码）：Default 组形状、user_count、重名 409、
// note 三态、404 与请求体双防线。
func TestContractUserGroupsListCreateUpdate(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))

	// 列表：seed 后仅 Default 组（apptest database.Seed，databk 在组内）。
	raw := cs.get(t, "/api/user-groups", admin, 200)
	m := decodeMap(t, raw)
	rows := m["data"].([]any)
	if len(rows) != 1 || m["total"].(float64) != 1 {
		t.Fatalf("groups = %d/%v, want 1/1", len(rows), m["total"])
	}
	def := rows[0].(map[string]any)
	for _, key := range []string{"guid", "name", "note", "is_default", "user_count"} {
		if _, has := def[key]; !has {
			t.Errorf("UserGroupView.%s missing", key)
		}
	}
	if def["name"] != "Default" || def["is_default"] != true {
		t.Errorf("default group = %v", def)
	}
	if def["user_count"] != float64(1) {
		t.Errorf("default user_count = %v, want 1（databk 管理员）", def["user_count"])
	}

	// scoped 无 user_groups.view → 403 Access denied。
	raw = cs.get(t, "/api/user-groups", scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAccessDenied {
		t.Errorf("no-perm message = %v, want %q", msg, rbac.MsgAccessDenied)
	}

	// 创建。
	raw = cs.post(t, "/api/user-groups", map[string]any{"name": "Engineering", "note": "eng"}, admin, 200)
	m = decodeMap(t, raw)
	guid, ok := m["guid"].(string)
	if !ok || guid == "" {
		t.Fatalf("created guid = %v", m["guid"])
	}
	if m["name"] != "Engineering" || m["note"] != "eng" || m["is_default"] != false || m["user_count"] != float64(0) {
		t.Errorf("created view = %v", m)
	}
	// 重名 409（大小写不敏感）。
	raw = cs.post(t, "/api/user-groups", map[string]any{"name": "engineering"}, admin, 409)
	if msg := decodeMap(t, raw)["message"]; msg != "User group name already exists" {
		t.Errorf("dup message = %v, want User group name already exists", msg)
	}
	// 请求体双防线：未知字段 / 缺 name。
	cs.invalid(t, http.MethodPost, "/api/user-groups", map[string]any{"name": "X", "evil": 1}, admin, 400)
	cs.invalid(t, http.MethodPost, "/api/user-groups", map[string]any{"note": "no name"}, admin, 400)

	// 更新：改名，note 未提供保持原值。
	raw = cs.raw(t, http.MethodPut, "/api/user-groups/"+guid, map[string]any{"name": "Engineering-2"}, admin, 200)
	if m = decodeMap(t, raw); m["name"] != "Engineering-2" || m["note"] != "eng" {
		t.Errorf("updated = %v, want name Engineering-2 / note eng", m)
	}
	// 改名撞 Default → 409；不存在 → 404。
	cs.raw(t, http.MethodPut, "/api/user-groups/"+guid, map[string]any{"name": "Default"}, admin, 409)
	raw = cs.raw(t, http.MethodPut, "/api/user-groups/no-such-guid", map[string]any{"name": "Z"}, admin, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "User group does not exist" {
		t.Errorf("404 message = %v, want User group does not exist", msg)
	}
}

// TestContractUserGroupMembersAndMove 成员查询（4 键形状、username ASC、
// search LIKE）与成员移动（user_groups.membership：命中计数、批量 404
// 整体拒绝、请求体 minItems/未知字段双防线）。
func TestContractUserGroupMembersAndMove(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	raw := cs.post(t, "/api/user-groups", map[string]any{"name": "Members"}, admin, 200)
	guid := decodeMap(t, raw)["guid"].(string)

	// 移动 scoped+global → moved_user_count=2（命中计数）。
	raw = cs.post(t, "/api/user-groups/"+guid+"/users", map[string]any{
		"user_guids": []string{seed.Scoped.Guid, seed.Global.Guid},
	}, admin, 200)
	if got := decodeMap(t, raw)["moved_user_count"]; got != float64(2) {
		t.Fatalf("moved_user_count = %v, want 2", got)
	}

	// 成员列表：username ASC + 4 键形状。
	raw = cs.get(t, "/api/user-groups/"+guid+"/users", admin, 200)
	m := decodeMap(t, raw)
	rows := m["data"].([]any)
	if len(rows) != 2 || m["total"].(float64) != 2 {
		t.Fatalf("members = %d/%v, want 2/2", len(rows), m["total"])
	}
	if rows[0].(map[string]any)["username"] != "global" || rows[1].(map[string]any)["username"] != "scoped" {
		t.Errorf("member order = %v/%v, want global/scoped（username ASC）",
			rows[0].(map[string]any)["username"], rows[1].(map[string]any)["username"])
	}
	for _, key := range []string{"guid", "username", "display_name", "email"} {
		if _, has := rows[0].(map[string]any)[key]; !has {
			t.Errorf("MemberView.%s missing", key)
		}
	}
	// 列表 user_count 同步。
	raw = cs.get(t, "/api/user-groups", admin, 200)
	for _, r := range decodeMap(t, raw)["data"].([]any) {
		if rm := r.(map[string]any); rm["name"] == "Members" && rm["user_count"] != float64(2) {
			t.Errorf("Members user_count = %v, want 2", rm["user_count"])
		}
	}

	// search LIKE：username / email 命中与未命中。
	raw = cs.get(t, "/api/user-groups/"+guid+"/users?search=sco", admin, 200)
	if rows := decodeMap(t, raw)["data"].([]any); len(rows) != 1 {
		t.Errorf("search sco = %d rows, want 1", len(rows))
	}
	raw = cs.get(t, "/api/user-groups/"+guid+"/users?search=seed-global", admin, 200)
	if rows := decodeMap(t, raw)["data"].([]any); len(rows) != 1 {
		t.Errorf("search email = %d rows, want 1", len(rows))
	}
	raw = cs.get(t, "/api/user-groups/"+guid+"/users?search=ghost", admin, 200)
	if rows := decodeMap(t, raw)["data"].([]any); len(rows) != 0 {
		t.Errorf("search ghost = %d rows, want 0", len(rows))
	}
	// 组不存在 → 404。
	raw = cs.get(t, "/api/user-groups/no-such-guid/users", admin, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "User group does not exist" {
		t.Errorf("members 404 message = %v", msg)
	}

	// 批量 404：任一 ghost → 复数文案，整体拒绝。
	raw = cs.post(t, "/api/user-groups/"+guid+"/users", map[string]any{
		"user_guids": []string{seed.Disabled.Guid, "ghost-user"},
	}, admin, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "One or more users do not exist" {
		t.Errorf("batch 404 message = %v, want One or more users do not exist", msg)
	}
	var count int64
	if err := as.DB.Model(&entity.User{}).
		Where("guid = ? AND userGroupGuid = ?", seed.Disabled.Guid, guid).
		Count(&count).Error; err != nil {
		t.Fatalf("count moved: %v", err)
	}
	if count != 0 {
		t.Error("batch 403 must be atomic, Disabled user must not be moved")
	}

	// 请求体双防线：minItems 1 / 未知字段。
	cs.invalid(t, http.MethodPost, "/api/user-groups/"+guid+"/users",
		map[string]any{"user_guids": []string{}}, admin, 400)
	cs.invalid(t, http.MethodPost, "/api/user-groups/"+guid+"/users",
		map[string]any{"user_guids": []string{"u"}, "evil": 1}, admin, 400)
}

// TestContractUserGroupDelete 默认组禁删 400；删除成员回落默认组
// （moved_user_count + deleted_rule_count 恒 0）；复删 404。
func TestContractUserGroupDelete(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	// Default guid 从列表取。
	defGuid := ""
	for _, r := range decodeMap(t, cs.get(t, "/api/user-groups", admin, 200))["data"].([]any) {
		if rm := r.(map[string]any); rm["is_default"] == true {
			defGuid = rm["guid"].(string)
		}
	}
	if defGuid == "" {
		t.Fatal("default group missing")
	}

	// 默认组禁删 → 400（固定文案）。
	raw := cs.delete(t, "/api/user-groups/"+defGuid, admin, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Default user group cannot be deleted" {
		t.Errorf("default delete message = %v, want Default user group cannot be deleted", msg)
	}

	// 建 Temp 组，移入 scoped+global，删除 → 成员回落 Default。
	raw = cs.post(t, "/api/user-groups", map[string]any{"name": "Temp"}, admin, 200)
	guid := decodeMap(t, raw)["guid"].(string)
	cs.post(t, "/api/user-groups/"+guid+"/users", map[string]any{
		"user_guids": []string{seed.Scoped.Guid, seed.Global.Guid},
	}, admin, 200)
	raw = cs.delete(t, "/api/user-groups/"+guid, admin, 200)
	m := decodeMap(t, raw)
	if m["moved_user_count"] != float64(2) || m["deleted_rule_count"] != float64(0) {
		t.Errorf("delete result = %v, want moved 2 / rules 0", m)
	}
	// Default user_count=3（databk+scoped+global 回落）。
	for _, r := range decodeMap(t, cs.get(t, "/api/user-groups", admin, 200))["data"].([]any) {
		if rm := r.(map[string]any); rm["is_default"] == true && rm["user_count"] != float64(3) {
			t.Errorf("default user_count after fallback = %v, want 3", rm["user_count"])
		}
	}
	// 复删 → 404。
	raw = cs.delete(t, "/api/user-groups/"+guid, admin, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "User group does not exist" {
		t.Errorf("re-delete message = %v", msg)
	}
}
