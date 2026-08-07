// strategy_contract_test.go 策略域契约用例：10 端点以 openapi.yaml 为
// 准绳双向校验。锁定：重名 400 文案、config_options 解析防御（非 string
// 值剔除/空串→{}）、DeleteWithDetach 三处置空、candidates 形状、
// target-candidates 两形态（device scope 过滤 / user 须 global）、
// assign/unassign 的 success/errors 形态与 reason 固定文案、
// target_guids 去重与 200 上限。
package contract

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// grantAssignChain 授予 strategies.assign 及其 requires 链
// （strategies.view + users.view）——缺依赖码时 FilterEffective 会剔除
// assign 码（共享知识 2 requires 链），scope 决策即视为无码。
func grantAssignChain(t *testing.T, as *apptest.AppServer, roleGuid string) {
	t.Helper()
	grantPermission(t, as, roleGuid, rbac.CodeStrategiesView)
	grantPermission(t, as, roleGuid, rbac.CodeUsersView)
	grantPermission(t, as, roleGuid, rbac.CodeStrategiesAssign)
}

// TestContractStrategyCRUD 列表/创建/详情/更新/删除全链：
// name LIKE + name ASC、config_options 三态、DeleteWithDetach 置空
// peers/users/device_groups 三处引用。
func TestContractStrategyCRUD(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))
	ctx := context.Background()

	// 列表：seed 1 条；其 config_options 含布尔值 → 防御剔除后 {}。
	raw := cs.get(t, "/api/strategies", hdr, 200)
	m := decodeMap(t, raw)
	rows := m["data"].([]any)
	if len(rows) != 1 || m["total"].(float64) != 1 {
		t.Fatalf("list = %d/%v, want 1/1", len(rows), m["total"])
	}
	s0 := rows[0].(map[string]any)
	for _, key := range []string{"guid", "name", "note", "config_options", "created_at", "updated_at"} {
		if _, has := s0[key]; !has {
			t.Errorf("StrategyView.%s missing", key)
		}
	}
	if opts := s0["config_options"].(map[string]any); len(opts) != 0 {
		t.Errorf("config_options = %v, want {}（非 string 值剔除）", opts)
	}

	// 创建：config_options 提供 → 原样读出。
	raw = cs.post(t, "/api/strategies", map[string]any{
		"name": "S2", "note": "x", "config_options": map[string]any{"access_ip": "10.0.0.9"},
	}, hdr, 200)
	m = decodeMap(t, raw)
	guid, ok := m["guid"].(string)
	if !ok || guid == "" {
		t.Fatalf("created guid = %v", m["guid"])
	}
	if opts := m["config_options"].(map[string]any); opts["access_ip"] != "10.0.0.9" {
		t.Errorf("created config_options = %v", m["config_options"])
	}

	// 重名 400（锁定与角色/用户组 409 的差异）+ 未知字段 400。
	raw = cs.post(t, "/api/strategies", map[string]any{"name": "sample-strategy"}, hdr, 400)
	if msg := decodeMap(t, raw)["message"]; msg != "Strategy name already exists" {
		t.Errorf("dup message = %v, want Strategy name already exists", msg)
	}
	cs.invalid(t, http.MethodPost, "/api/strategies", map[string]any{"name": "S3", "evil": 1}, hdr, 400)

	// 详情 + 404。
	raw = cs.get(t, "/api/strategies/"+guid, hdr, 200)
	if decodeMap(t, raw)["name"] != "S2" {
		t.Errorf("get = %s", raw)
	}
	raw = cs.get(t, "/api/strategies/no-such-guid", hdr, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "Strategy not found" {
		t.Errorf("404 message = %v, want Strategy not found", msg)
	}

	// 更新：config_options 提供即覆盖；note 未提供保持原值。
	raw = cs.patch(t, "/api/strategies/"+guid, map[string]any{
		"name": "S2", "config_options": map[string]any{"k": "v"},
	}, hdr, 200)
	m = decodeMap(t, raw)
	if m["note"] != "x" || m["config_options"].(map[string]any)["k"] != "v" {
		t.Errorf("updated = note %v options %v, want x/{k:v}", m["note"], m["config_options"])
	}
	cs.patch(t, "/api/strategies/"+guid, map[string]any{"name": "sample-strategy"}, hdr, 400)
	cs.patch(t, "/api/strategies/no-such-guid", map[string]any{"name": "Z"}, hdr, 404)

	// 删除：先挂三处引用（peer/user/device_group），删除后全部置空。
	if err := as.DB.Model(&entity.Peer{}).Where("uuid = ?", seed.PeerB.UUID).
		Update("strategyGuid", guid).Error; err != nil {
		t.Fatalf("bind peer: %v", err)
	}
	if err := as.DB.Model(&entity.DeviceGroup{}).Where("guid = ?", seed.DG2.Guid).
		Update("strategyGuid", guid).Error; err != nil {
		t.Fatalf("bind group: %v", err)
	}
	if err := as.DB.Model(&entity.User{}).Where("guid = ?", seed.Global.Guid).
		Update("strategyGuid", guid).Error; err != nil {
		t.Fatalf("bind user: %v", err)
	}
	raw = cs.delete(t, "/api/strategies/"+guid, hdr, 200)
	if m := decodeMap(t, raw); len(m) != 0 {
		t.Errorf("delete response = %v, want empty object", m)
	}
	peer, err := repository.NewPeerRepo(as.DB).FindByUUID(ctx, seed.PeerB.UUID)
	if err != nil || peer.StrategyGuid != nil {
		t.Errorf("peer.strategyGuid not detached: %v/%v", peer.StrategyGuid, err)
	}
	user, err := repository.NewUserRepo(as.DB).FindByGuid(ctx, seed.Global.Guid)
	if err != nil || user.StrategyGuid != nil {
		t.Errorf("user.strategyGuid not detached: %v/%v", user.StrategyGuid, err)
	}
	group, err := repository.NewDeviceGroupRepo(as.DB).FindByID(ctx, seed.DG2.Guid)
	if err != nil || group.StrategyGuid != nil {
		t.Errorf("group.strategyGuid not detached: %v/%v", group.StrategyGuid, err)
	}
	// 复删 → 404。
	cs.delete(t, "/api/strategies/"+guid, hdr, 404)
}

// TestContractStrategyCandidates candidates（Perm(strategies.assign)）：
// 三键形状、name ASC；无码 403；授权后可见。
func TestContractStrategyCandidates(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))

	// 无 strategies.assign → 403 Access denied。
	raw := cs.get(t, "/api/strategies/candidates", scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAccessDenied {
		t.Errorf("no-perm message = %v, want %q", msg, rbac.MsgAccessDenied)
	}

	cs.post(t, "/api/strategies", map[string]any{"name": "another-strategy"}, hdr, 200)
	rows := decodeMap(t, cs.get(t, "/api/strategies/candidates", hdr, 200))["data"].([]any)
	if len(rows) != 2 {
		t.Fatalf("candidates = %d rows, want 2", len(rows))
	}
	first := rows[0].(map[string]any)
	if first["name"] != "another-strategy" {
		t.Errorf("order by name ASC broken: first = %v", first["name"])
	}
	for _, key := range []string{"guid", "name", "note"} {
		if _, has := first[key]; !has {
			t.Errorf("StrategyCandidateView.%s missing", key)
		}
	}

	// 授权后 scoped 可见全量候选（候选无 scope 过滤语义）。
	grantAssignChain(t, as, seed.RoleDev.Guid)
	rows = decodeMap(t, cs.get(t, "/api/strategies/candidates", scopedHdr, 200))["data"].([]any)
	if len(rows) != 2 {
		t.Errorf("scoped candidates = %d rows, want 2", len(rows))
	}
}

// TestContractStrategyTargetCandidates target-candidates（两形态）：
// device scope 过滤；user 须 global（403 固定文案）、非管理员操作者
// 仅见非管理员用户、is_protected 判定；非法 target_type 400。
func TestContractStrategyTargetCandidates(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))
	grantAssignChain(t, as, seed.RoleDev.Guid)

	// device 形态 admin：3 行 {uuid,id} id ASC。
	raw := cs.get(t, "/api/strategies/target-candidates?target_type=device", hdr, 200)
	rows := decodeMap(t, raw)["data"].([]any)
	if len(rows) != 3 {
		t.Fatalf("admin device candidates = %d rows, want 3", len(rows))
	}
	first := rows[0].(map[string]any)
	if first["uuid"] != seed.PeerA.UUID || first["id"] != "1000001" {
		t.Errorf("first = %v, want PeerA/1000001", first)
	}
	// device 形态 scoped：仅 DG1 内 PeerA。
	rows = decodeMap(t, cs.get(t, "/api/strategies/target-candidates?target_type=device", scopedHdr, 200))["data"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["uuid"] != seed.PeerA.UUID {
		t.Errorf("scoped device candidates = %v, want [PeerA]", rows)
	}

	// user 形态 admin：全量用户（含管理员/保护账号），is_protected 判定。
	rows = decodeMap(t, cs.get(t, "/api/strategies/target-candidates?target_type=user", hdr, 200))["data"].([]any)
	if len(rows) != 5 {
		t.Fatalf("admin user candidates = %d rows, want 5（databk 超管 + 4 seed）", len(rows))
	}
	byGuid := map[string]map[string]any{}
	for _, r := range rows {
		row := r.(map[string]any)
		byGuid[row["guid"].(string)] = row
	}
	if byGuid[seed.Owner.Guid]["is_protected"] != true {
		t.Errorf("owner is_protected = %v, want true（保护角色）", byGuid[seed.Owner.Guid])
	}
	if byGuid[seed.Admin.Guid]["is_protected"] != true {
		t.Errorf("admin is_protected = %v, want true（isAdmin）", byGuid[seed.Admin.Guid])
	}
	if byGuid[seed.Scoped.Guid]["is_protected"] != false || byGuid[seed.Scoped.Guid]["name"] != "scoped" {
		t.Errorf("scoped row = %v, want name=scoped protected=false", byGuid[seed.Scoped.Guid])
	}

	// user 形态 scoped（非 global）→ 403 固定文案。
	raw = cs.get(t, "/api/strategies/target-candidates?target_type=user", scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAssignUserGlobal {
		t.Errorf("scoped user-form message = %v, want %q", msg, rbac.MsgAssignUserGlobal)
	}

	// 非管理员 global 操作者：仅见非管理员用户（4 行，排除超管）。
	grantAssignChain(t, as, seed.RoleGlobal.Guid)
	globalHdr := bearer(m2Token(t, as, seed.Global))
	rows = decodeMap(t, cs.get(t, "/api/strategies/target-candidates?target_type=user", globalHdr, 200))["data"].([]any)
	if len(rows) != 4 {
		t.Fatalf("global non-admin user candidates = %d rows, want 4", len(rows))
	}
	for _, r := range rows {
		if r.(map[string]any)["guid"] == seed.Admin.Guid {
			t.Error("non-admin operator must NOT see admin user")
		}
	}

	// 非法 target_type → 400（enum 双防线）。
	cs.invalid(t, http.MethodGet, "/api/strategies/target-candidates?target_type=ghost", nil, hdr, 400)
}

// TestContractStrategyAssignments assignments（三形态 + target_type 必填）：
// device/device_group 按 scope 过滤；user 须 global；404；非法/缺失
// target_type 400。
func TestContractStrategyAssignments(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))
	ctx := context.Background()

	// 绑定前置：PeerA/DG1 由 seed 已挂 seed-strategy-1；再挂 scoped 用户。
	if err := repository.NewUserRepo(as.DB).UpdateColumnsByGuids(ctx, []string{seed.Scoped.Guid},
		map[string]any{"strategyGuid": seed.StrategyS.Guid}); err != nil {
		t.Fatalf("bind user strategy: %v", err)
	}
	sid := seed.StrategyS.Guid

	// device 形态：PeerA。
	rows := decodeMap(t, cs.get(t, "/api/strategies/"+sid+"/assignments?target_type=device", hdr, 200))["data"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["uuid"] != seed.PeerA.UUID {
		t.Fatalf("device assignments = %v, want [PeerA]", rows)
	}
	// device_group 形态：DG1（name ASC）。
	rows = decodeMap(t, cs.get(t, "/api/strategies/"+sid+"/assignments?target_type=device_group", hdr, 200))["data"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["guid"] != seed.DG1.Guid || rows[0].(map[string]any)["name"] != "Alpha" {
		t.Fatalf("group assignments = %v, want [DG1]", rows)
	}
	// user 形态：scoped。
	rows = decodeMap(t, cs.get(t, "/api/strategies/"+sid+"/assignments?target_type=user", hdr, 200))["data"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["guid"] != seed.Scoped.Guid {
		t.Fatalf("user assignments = %v, want [scoped]", rows)
	}

	// 404；缺失/非法 target_type 400（required/enum 双防线）。
	cs.get(t, "/api/strategies/no-such-guid/assignments?target_type=device", hdr, 404)
	cs.invalid(t, http.MethodGet, "/api/strategies/"+sid+"/assignments", nil, hdr, 400)
	cs.invalid(t, http.MethodGet, "/api/strategies/"+sid+"/assignments?target_type=ghost", nil, hdr, 400)

	// scoped：device 形态 scope 过滤（PeerA 在 DG1 内）→ 1 行；
	// user 形态非 global → 403 固定文案。
	grantAssignChain(t, as, seed.RoleDev.Guid)
	rows = decodeMap(t, cs.get(t, "/api/strategies/"+sid+"/assignments?target_type=device", scopedHdr, 200))["data"].([]any)
	if len(rows) != 1 {
		t.Errorf("scoped device assignments = %d rows, want 1", len(rows))
	}
	raw := cs.get(t, "/api/strategies/"+sid+"/assignments?target_type=user", scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAssignUserGlobal {
		t.Errorf("scoped user-form message = %v, want %q", msg, rbac.MsgAssignUserGlobal)
	}
}

// TestContractStrategyAssignUnassign §4.4 主链：assign 部分成功
// {success,errors} 与 reason 固定文案、宿主表回写、unassign 二次解绑
// not bound 文案、scoped 403 两分支、去重、200 上限、404。
func TestContractStrategyAssignUnassign(t *testing.T) {
	cs, as, seed := newGroupStrategyServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))
	ctx := context.Background()
	sid := seed.StrategyS.Guid
	peerRepo := repository.NewPeerRepo(as.DB)

	// ---- assign device_group：DG2 成功 + ghost 记 errors ----
	raw := cs.post(t, "/api/strategies/"+sid+"/assign", map[string]any{
		"target_type": "device_group", "target_guids": []string{seed.DG2.Guid, "ghost-dg"},
	}, hdr, 200)
	m := decodeMap(t, raw)
	if success := m["success"].([]any); len(success) != 1 || success[0] != seed.DG2.Guid {
		t.Fatalf("success = %v, want [DG2]", m["success"])
	}
	errs := m["errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want 1 item", m["errors"])
	}
	e0 := errs[0].(map[string]any)
	if e0["target_guid"] != "ghost-dg" || e0["reason"] != "Device group not found" {
		t.Errorf("error item = %v, want ghost-dg/Device group not found", e0)
	}
	group, err := repository.NewDeviceGroupRepo(as.DB).FindByID(ctx, seed.DG2.Guid)
	if err != nil || group.StrategyGuid == nil || *group.StrategyGuid != sid {
		t.Fatalf("DG2.strategyGuid not written: %v/%v", group.StrategyGuid, err)
	}

	// ---- assign device：PeerB 成功 + ghost 讀 errors ----
	raw = cs.post(t, "/api/strategies/"+sid+"/assign", map[string]any{
		"target_type": "device", "target_guids": []string{seed.PeerB.UUID, "ghost-peer"},
	}, hdr, 200)
	m = decodeMap(t, raw)
	errs = m["errors"].([]any)
	if len(m["success"].([]any)) != 1 || errs[0].(map[string]any)["reason"] != "Device not found" {
		t.Errorf("device assign = %v", m)
	}
	p, _ := peerRepo.FindByUUID(ctx, seed.PeerB.UUID)
	if p.StrategyGuid == nil || *p.StrategyGuid != sid {
		t.Errorf("PeerB.strategyGuid not written")
	}

	// ---- assign user：scoped ----
	raw = cs.post(t, "/api/strategies/"+sid+"/assign", map[string]any{
		"target_type": "user", "target_guids": []string{seed.Scoped.Guid},
	}, hdr, 200)
	if success := decodeMap(t, raw)["success"].([]any); len(success) != 1 {
		t.Errorf("user assign success = %v", decodeMap(t, raw)["success"])
	}
	u, _ := repository.NewUserRepo(as.DB).FindByGuid(ctx, seed.Scoped.Guid)
	if u.StrategyGuid == nil || *u.StrategyGuid != sid {
		t.Errorf("scoped.strategyGuid not written")
	}

	// ---- unassign：置空 + not bound 文案 ----
	raw = cs.post(t, "/api/strategies/"+sid+"/unassign", map[string]any{
		"target_type": "device_group", "target_guids": []string{seed.DG2.Guid},
	}, hdr, 200)
	if success := decodeMap(t, raw)["success"].([]any); len(success) != 1 {
		t.Fatalf("unassign success = %v", decodeMap(t, raw)["success"])
	}
	group, _ = repository.NewDeviceGroupRepo(as.DB).FindByID(ctx, seed.DG2.Guid)
	if group.StrategyGuid != nil {
		t.Errorf("DG2.strategyGuid = %v, want nil", *group.StrategyGuid)
	}
	raw = cs.post(t, "/api/strategies/"+sid+"/unassign", map[string]any{
		"target_type": "device_group", "target_guids": []string{seed.DG2.Guid},
	}, hdr, 200)
	errs = decodeMap(t, raw)["errors"].([]any)
	if len(errs) != 1 || errs[0].(map[string]any)["reason"] != "Device group is not bound to this strategy" {
		t.Errorf("re-unassign = %v, want not bound 文案", decodeMap(t, raw)["errors"])
	}
	// unassign 未绑定过的用户 → not bound 文案（user 形态）。
	raw = cs.post(t, "/api/strategies/"+sid+"/unassign", map[string]any{
		"target_type": "user", "target_guids": []string{seed.Global.Guid},
	}, hdr, 200)
	errs = decodeMap(t, raw)["errors"].([]any)
	if len(errs) != 1 || errs[0].(map[string]any)["reason"] != "User is not bound to this strategy" {
		t.Errorf("user not-bound = %v", errs)
	}

	// ---- scoped 操作者：scope 外组 403 固定文案；scope 内成功；user 403 ----
	grantAssignChain(t, as, seed.RoleDev.Guid)
	raw = cs.post(t, "/api/strategies/"+sid+"/assign", map[string]any{
		"target_type": "device_group", "target_guids": []string{seed.DG2.Guid},
	}, scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgTargetGroupOutside {
		t.Errorf("outside-scope message = %v, want %q", msg, rbac.MsgTargetGroupOutside)
	}
	raw = cs.post(t, "/api/strategies/"+sid+"/assign", map[string]any{
		"target_type": "device_group", "target_guids": []string{seed.DG1.Guid},
	}, scopedHdr, 200)
	if success := decodeMap(t, raw)["success"].([]any); len(success) != 1 {
		t.Errorf("in-scope assign = %v", decodeMap(t, raw)["success"])
	}
	raw = cs.post(t, "/api/strategies/"+sid+"/assign", map[string]any{
		"target_type": "user", "target_guids": []string{seed.Scoped.Guid},
	}, scopedHdr, 403)
	if msg := decodeMap(t, raw)["message"]; msg != rbac.MsgAssignUserGlobal {
		t.Errorf("scoped assign-user message = %v, want %q", msg, rbac.MsgAssignUserGlobal)
	}

	// ---- 去重：重复 guid success 仅一项 ----
	raw = cs.post(t, "/api/strategies/"+sid+"/assign", map[string]any{
		"target_type": "device_group", "target_guids": []string{seed.DG2.Guid, seed.DG2.Guid},
	}, hdr, 200)
	if success := decodeMap(t, raw)["success"].([]any); len(success) != 1 {
		t.Errorf("dedup success = %v, want 1 item", success)
	}

	// ---- 404：策略不存在 ----
	raw = cs.post(t, "/api/strategies/no-such-guid/assign", map[string]any{
		"target_type": "device_group", "target_guids": []string{seed.DG1.Guid},
	}, hdr, 404)
	if msg := decodeMap(t, raw)["message"]; msg != "Strategy not found" {
		t.Errorf("404 message = %v", msg)
	}

	// ---- 200 上限：201 个目标 → 400（maxItems 双防线）----
	big := make([]string, 201)
	for i := range big {
		big[i] = "t-" + strconv.Itoa(i)
	}
	cs.invalid(t, http.MethodPost, "/api/strategies/"+sid+"/assign", map[string]any{
		"target_type": "device", "target_guids": big,
	}, hdr, 400)
}
