// devicegroup_contract_test.go 设备组域契约用例：8 端点以 openapi.yaml
// 为准绳双向校验。锁定：重名 400（与角色/用户组 409 的差异）、AdminGuard
// 文案、被角色授权引用的组删除 400、accessible 三源形状、加减设备按
// peer.id 命中的 added/removed_count 语义、strategy-targets scope 边界。
package contract

import (
	"context"
	"net/http"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// newGroupStrategyServer 设备组/策略域契约服务器（复用设备协议基建：
// 真实路由 + 内存库 + SeedM2，禁 per-IP 限流）。
func newGroupStrategyServer(t *testing.T) (*contractServer, *apptest.AppServer, *testutil.SeedM2Data) {
	t.Helper()
	return newDeviceProtocolServer(t)
}

// TestContractDeviceGroupListAdmin 列表（AdminGuard）：name ASC、
// 7 必需键、device_count 批量计数、strategy_guid 可空、name LIKE、分页。
func TestContractDeviceGroupListAdmin(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))

	raw := cs.get(t, "/api/device-groups", hdr, 200)
	m := decodeMap(t, raw)
	rows, ok := m["data"].([]any)
	if !ok {
		t.Fatalf("data missing: %v", m)
	}
	if len(rows) != 2 || m["total"].(float64) != 2 {
		t.Fatalf("rows = %d total = %v, want 2/2", len(rows), m["total"])
	}
	first := rows[0].(map[string]any)
	if first["name"] != "Alpha" {
		t.Errorf("order by name ASC broken: first = %v", first["name"])
	}
	for _, key := range []string{"guid", "name", "note", "strategy_guid", "device_count", "created_at", "updated_at"} {
		if _, has := first[key]; !has {
			t.Errorf("DeviceGroupView.%s missing", key)
		}
	}
	if first["device_count"] != float64(1) {
		t.Errorf("DG1 device_count = %v, want 1（PeerA 在组内）", first["device_count"])
	}
	if first["strategy_guid"] != seed.StrategyS.Guid {
		t.Errorf("DG1 strategy_guid = %v, want %s", first["strategy_guid"], seed.StrategyS.Guid)
	}
	second := rows[1].(map[string]any)
	if second["name"] != "Beta" || second["strategy_guid"] != nil {
		t.Errorf("DG2 = name %v strategy_guid %v, want Beta/null", second["name"], second["strategy_guid"])
	}

	// name LIKE：'Be' 前缀命中 Beta（避开 SQLite LIKE 大小写歧义）。
	raw = cs.get(t, "/api/device-groups?name=Be", hdr, 200)
	if rows := decodeMap(t, raw)["data"].([]any); len(rows) != 1 {
		t.Errorf("name LIKE filter = %d rows, want 1", len(rows))
	}
	// 分页：pageSize=1 第二页。
	raw = cs.get(t, "/api/device-groups?current=2&pageSize=1", hdr, 200)
	m = decodeMap(t, raw)
	if len(m["data"].([]any)) != 1 || m["total"].(float64) != 2 {
		t.Errorf("page 2 = %v", m)
	}

	// AdminGuard：scoped 用户 403 固定文案（device-groups 路线，
	// 与 roles 路线 "Super administrator permission required" 区分）。
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))
	raw = cs.get(t, "/api/device-groups", scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAdminGuardRequired {
		t.Errorf("admin guard message = %v, want %q", msg, rbac.MsgAdminGuardRequired)
	}
}

// TestContractDeviceGroupCreateAndUpdate 创建/更新：重名 400 文案、
// note 三态（未提供保持原值）、404 "Device group does not exist"。
func TestContractDeviceGroupCreateAndUpdate(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))

	raw := cs.post(t, "/api/device-groups", map[string]any{"name": "Gamma", "note": "n1"}, hdr, 200)
	m := decodeMap(t, raw)
	guid, ok := m["guid"].(string)
	if !ok || guid == "" {
		t.Fatalf("created guid = %v", m["guid"])
	}
	if m["note"] != "n1" || m["strategy_guid"] != nil || m["device_count"] != float64(0) {
		t.Errorf("created view = %v", m)
	}

	// 重名 400（锁定与角色/用户组 409 的差异）。
	raw = cs.post(t, "/api/device-groups", map[string]any{"name": "Alpha"}, hdr, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Device group name already exists" {
		t.Errorf("dup message = %v, want Device group name already exists", msg)
	}
	// 未知字段 400（additionalProperties:false 双防线）。
	cs.invalid(t, http.MethodPost, "/api/device-groups",
		map[string]any{"name": "X", "evil": 1}, hdr, 400)

	// 更新：改名，note 未提供保持原值。
	raw = cs.patch(t, "/api/device-groups/"+guid, map[string]any{"name": "Delta"}, hdr, 200)
	m = decodeMap(t, raw)
	if m["name"] != "Delta" || m["note"] != "n1" {
		t.Errorf("updated = name %v note %v, want Delta/n1", m["name"], m["note"])
	}
	// 更新重名 → 400；404。
	cs.patch(t, "/api/device-groups/"+guid, map[string]any{"name": "Beta"}, hdr, 400)
	raw = cs.patch(t, "/api/device-groups/no-such-guid", map[string]any{"name": "Z"}, hdr, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "Device group does not exist" {
		t.Errorf("404 message = %v, want Device group does not exist", msg)
	}
	// 创建后列表总数 3（seed 两组 + Gamma→Delta）。
	if total := decodeMap(t, cs.get(t, "/api/device-groups", hdr, 200))["total"]; total != float64(3) {
		t.Errorf("total after create = %v, want 3", total)
	}
}

// TestContractDeviceGroupDeleteAndReference 删除：被角色授权引用 400
// （RESTRICT 应用层计数）；删除后组内设备归属置空（服务层事务级联）。
func TestContractDeviceGroupDeleteAndReference(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))
	ctx := context.Background()

	// PeerB 加入 DG2，删除组后归属应置空。
	raw := cs.raw(t, http.MethodPost, "/api/device-groups/"+seed.DG2.Guid, []string{seed.PeerB.ID}, hdr, 200)
	if decodeMap(t, raw)["added_count"] != float64(1) {
		t.Fatalf("add device to DG2 failed: %s", raw)
	}

	// 角色授权引用 → 400（seed-asg-dev 已引用 DG1，再引 DG2）。
	if err := as.DB.Create(&entity.UserRoleAssignmentDeviceGroup{
		AssignmentGuid: "seed-asg-dev", DeviceGroupGuid: seed.DG2.Guid,
	}).Error; err != nil {
		t.Fatalf("seed role ref: %v", err)
	}
	raw = cs.delete(t, "/api/device-groups/"+seed.DG2.Guid, hdr, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Device group is referenced by role assignments" {
		t.Errorf("referenced message = %v", msg)
	}

	// 解除引用后可删；删除后 PeerB 归属置空（方言无关级联）。
	if err := as.DB.Where("deviceGroupGuid = ?", seed.DG2.Guid).
		Delete(&entity.UserRoleAssignmentDeviceGroup{}).Error; err != nil {
		t.Fatalf("remove role ref: %v", err)
	}
	raw = cs.delete(t, "/api/device-groups/"+seed.DG2.Guid, hdr, 200)
	if m := decodeMap(t, raw); len(m) != 0 {
		t.Errorf("delete response = %v, want empty object", m)
	}
	p, err := repository.NewPeerRepo(as.DB).FindByUUID(ctx, seed.PeerB.UUID)
	if err != nil {
		t.Fatalf("peer missing: %v", err)
	}
	if p.DeviceGroupGuid != nil {
		t.Errorf("peer.deviceGroupGuid = %v, want nil（组删后置空）", *p.DeviceGroupGuid)
	}
	// 复删 → 404。
	raw = cs.delete(t, "/api/device-groups/"+seed.DG2.Guid, hdr, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "Device group does not exist" {
		t.Errorf("re-delete message = %v", msg)
	}
}

// TestContractDeviceGroupAccessible accessible（Auth+状态复核）：
// 管理员全量；scoped = devices.view scope ∪ dgup（同落 DG1）；
// global 用户 scope 全量；三键形状；被禁用户 401 固定文案。
func TestContractDeviceGroupAccessible(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))

	raw := cs.get(t, "/api/device-group/accessible", hdr, 200)
	m := decodeMap(t, raw)
	rows := m["data"].([]any)
	if len(rows) != 2 || m["total"].(float64) != 2 {
		t.Fatalf("admin accessible = %d/%v, want 2/2", len(rows), m["total"])
	}
	first := rows[0].(map[string]any)
	for _, key := range []string{"guid", "name", "note"} {
		if _, has := first[key]; !has {
			t.Errorf("AccessibleGroupView.%s missing", key)
		}
	}
	if _, has := first["device_count"]; has {
		t.Error("AccessibleGroupView must NOT contain device_count（三键形状锁定）")
	}

	// name LIKE。
	if rows := decodeMap(t, cs.get(t, "/api/device-group/accessible?name=Be", hdr, 200))["data"].([]any); len(rows) != 1 {
		t.Errorf("name LIKE = %d rows, want 1", len(rows))
	}

	// scoped：devices.view@DG1 ∪ dgup@DG1 → 仅 DG1。
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))
	rows = decodeMap(t, cs.get(t, "/api/device-group/accessible", scopedHdr, 200))["data"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["guid"] != seed.DG1.Guid {
		t.Errorf("scoped accessible = %v, want [DG1]", rows)
	}

	// global 用户：devices.view global scope → 全量。
	globalHdr := bearer(m2Token(t, as, seed.Global))
	rows = decodeMap(t, cs.get(t, "/api/device-group/accessible", globalHdr, 200))["data"].([]any)
	if len(rows) != 2 {
		t.Errorf("global accessible = %d rows, want 2", len(rows))
	}

	// 无 token → 401；被禁用户 → 401 固定文案。
	cs.get(t, "/api/device-group/accessible", nil, 401)
	raw = cs.get(t, "/api/device-group/accessible", bearer(m2Token(t, as, seed.Disabled)), 401)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAccountDisabled {
		t.Errorf("disabled message = %v, want %q", msg, rbac.MsgAccountDisabled)
	}
}

// TestContractDeviceGroupStrategyTargets strategy-targets
// （Perm(strategies.assign)）：无码 403 Access denied；scoped 仅授权组
// （guid ASC）；admin 全量；两键形状。
func TestContractDeviceGroupStrategyTargets(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))

	// Scoped 未持 strategies.assign → 403 Access denied。
	raw := cs.get(t, "/api/device-groups/strategy-targets", scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAccessDenied {
		t.Errorf("no-perm message = %v, want %q", msg, rbac.MsgAccessDenied)
	}

	// 授权后：scope=DG1 → 仅 DG1。
	grantAssignChain(t, as, seed.RoleDev.Guid)
	rows := decodeMap(t, cs.get(t, "/api/device-groups/strategy-targets", scopedHdr, 200))["data"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["guid"] != seed.DG1.Guid {
		t.Fatalf("scoped targets = %v, want [DG1]", rows)
	}
	for _, key := range []string{"guid", "name"} {
		if _, has := rows[0].(map[string]any)[key]; !has {
			t.Errorf("DeviceGroupTargetView.%s missing", key)
		}
	}

	// admin 全量，guid ASC。
	rows = decodeMap(t, cs.get(t, "/api/device-groups/strategy-targets", hdr, 200))["data"].([]any)
	if len(rows) != 2 || rows[0].(map[string]any)["guid"] != seed.DG1.Guid {
		t.Errorf("admin targets = %v, want [DG1,DG2] guid ASC", rows)
	}
}

// TestContractDeviceGroupAddRemoveDevices 加减设备（body=peer.id[]）：
// added_count=命中数（已在本组亦计、不存在不计）；removed_count=实际
// 移出本组数；空数组 400 双防线；404。
func TestContractDeviceGroupAddRemoveDevices(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))
	ctx := context.Background()
	peerRepo := repository.NewPeerRepo(as.DB)

	// PeerB（未分组）加入 DG2。
	raw := cs.raw(t, http.MethodPost, "/api/device-groups/"+seed.DG2.Guid,
		[]string{seed.PeerB.ID}, hdr, 200)
	if decodeMap(t, raw)["added_count"] != float64(1) {
		t.Fatalf("added_count = %s", raw)
	}
	p, err := peerRepo.FindByUUID(ctx, seed.PeerB.UUID)
	if err != nil || p.DeviceGroupGuid == nil || *p.DeviceGroupGuid != seed.DG2.Guid {
		t.Fatalf("peer not grouped: %v/%v", p.DeviceGroupGuid, err)
	}

	// 再次加入（已在本组亦计）+ 不存在 ID 不计。
	raw = cs.raw(t, http.MethodPost, "/api/device-groups/"+seed.DG2.Guid,
		[]string{seed.PeerB.ID, "999999"}, hdr, 200)
	if got := decodeMap(t, raw)["added_count"]; got != float64(1) {
		t.Errorf("added_count with ghost = %v, want 1", got)
	}

	// 空数组 → 400（openapi minItems 双防线）。
	cs.invalid(t, http.MethodPost, "/api/device-groups/"+seed.DG2.Guid, []string{}, hdr, 400)
	// 组不存在 → 404。
	cs.raw(t, http.MethodPost, "/api/device-groups/no-such-guid", []string{"1"}, hdr, 404)

	// 移出：命中 PeerB，ghost 不计。
	raw = cs.raw(t, http.MethodDelete, "/api/device-groups/"+seed.DG2.Guid+"/devices",
		[]string{seed.PeerB.ID, "888888"}, hdr, 200)
	if decodeMap(t, raw)["removed_count"] != float64(1) {
		t.Fatalf("removed_count = %s", raw)
	}
	p, _ = peerRepo.FindByUUID(ctx, seed.PeerB.UUID)
	if p.DeviceGroupGuid != nil {
		t.Errorf("peer.deviceGroupGuid = %v, want nil（已移出）", *p.DeviceGroupGuid)
	}
	// 移出接口 404。
	cs.raw(t, http.MethodDelete, "/api/device-groups/no-such-guid/devices", []string{"1"}, hdr, 404)
}
