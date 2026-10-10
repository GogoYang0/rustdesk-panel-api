// device_contract_test.go 设备域契约用例：/peers 与 /devices×6 以
// openapi.yaml 为准绳双向校验，锁定同表两视图的形状差异（DeviceView
// 的 userGuid/deviceGroupGuid 双键 / PeerView 无此二键）与过滤语义差异
// （device_group_name 在 /peers LIKE、在 /devices 精确）。
package contract

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// newDeviceContractServer 契约服务器（复用设备协议基建，显式类型）。
func newDeviceContractServer(t *testing.T) (*contractServer, *apptest.AppServer, *testutil.SeedM2Data) {
	t.Helper()
	return newDeviceProtocolServer(t)
}

// grantPermission 为角色补授权限码（测试内构造 devices.edit/status
// 操作者；生产经 roles API 指派，属 T05 域）。
func grantPermission(t *testing.T, as *apptest.AppServer, roleGuid, code string) {
	t.Helper()
	if err := as.DB.Create(&entity.RolePermission{RoleGuid: roleGuid, PermissionCode: code}).Error; err != nil {
		t.Fatalf("grant %s to %s: %v", code, roleGuid, err)
	}
}

// TestContractPeersAdmin 管理员全量（含未分组），peer.id ASC 排序；
// PeerView 形状锁定：必需 11 键齐全、无 userGuid/deviceGroupGuid。
func TestContractPeersAdmin(t *testing.T) {
	cs, as, seed := newDeviceContractServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))
	raw := cs.get(t, "/api/peers", hdr, 200)
	m := decodeMap(t, raw)
	rows, ok := m["data"].([]any)
	if !ok {
		t.Fatalf("data missing: %v", m)
	}
	if len(rows) != 3 {
		t.Fatalf("admin sees %d peers, want 3（含未分组 PeerB）", len(rows))
	}
	first, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("row[0] not object: %v", rows[0])
	}
	if first["id"] != "1000001" {
		t.Errorf("order by peer.id ASC broken: first id = %v", first["id"])
	}
	for _, key := range []string{"id", "guid", "status", "is_online", "last_online",
		"user", "user_name", "note", "device_group_name", "strategy_name", "info"} {
		if _, has := first[key]; !has {
			t.Errorf("PeerView.%s missing", key)
		}
	}
	if _, has := first["userGuid"]; has {
		t.Error("PeerView must NOT contain userGuid（形状差异锁定）")
	}
	if _, has := first["deviceGroupGuid"]; has {
		t.Error("PeerView must NOT contain deviceGroupGuid（形状差异锁定）")
	}
	if first["guid"] != seed.PeerA.UUID {
		t.Errorf("guid = %v, want peer.uuid %s", first["guid"], seed.PeerA.UUID)
	}
	if first["is_online"] != true {
		t.Errorf("PeerA is_online = %v, want true（10s 前心跳）", first["is_online"])
	}
	info := first["info"].(map[string]any)
	if info["device_name"] != "alpha-host" || info["version"] != "1.1.0" || info["ip"] != "" {
		t.Errorf("info = %v", info)
	}
}

// TestContractPeersThreeSourceVisibility 三源可见性：Scoped = own(PeerA)
// ∪ dgup(DG1→PeerA)；Owner = own(PeerC) ∪ uup（uup.userGuid=被授权方
// owner 可见 uup.targetUserGuid=scoped 名下设备 → PeerA）；Global 仅 own。
func TestContractPeersThreeSourceVisibility(t *testing.T) {
	cs, as, seed := newDeviceContractServer(t)

	scopedHdr := bearer(m2Token(t, as, seed.Scoped))
	rows := peerRows(t, cs, "/api/peers", scopedHdr)
	if len(rows) != 1 || rows[0]["id"] != "1000001" {
		t.Fatalf("scoped sees %v, want PeerA（own ∪ dgup 同设备）", idsOf(rows))
	}

	// 源三：user_user_permissions（owner → scoped 的设备可见）。
	ownerHdr := bearer(m2Token(t, as, seed.Owner))
	rows = peerRows(t, cs, "/api/peers", ownerHdr)
	ids := idsOf(rows)
	if len(rows) != 2 || !contains(ids, "1000001") || !contains(ids, "1000003") {
		t.Errorf("owner sees %v, want {1000001,1000003}（own PeerC ∪ uup 得 PeerA）", ids)
	}

	globalHdr := bearer(m2Token(t, as, seed.Global))
	rows = peerRows(t, cs, "/api/peers", globalHdr)
	if len(rows) != 1 || rows[0]["id"] != "1000002" {
		t.Errorf("global-user sees %v, want only own PeerB（无授权关系）", idsOf(rows))
	}

	// 无 token → 401。
	cs.get(t, "/api/peers", nil, 401)
}

// TestContractPeersFilters /peers 过滤语义：id/os/device_group_name 均
// LIKE；is_online 枚举；分页 data/total。
func TestContractPeersFilters(t *testing.T) {
	cs, as, seed := newDeviceContractServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))

	// id LIKE：子串命中。
	if rows := peerRows(t, cs, "/api/peers?id=000001", hdr); len(rows) != 1 {
		t.Errorf("id LIKE filter = %d rows, want 1", len(rows))
	}
	// os LIKE（查 sysinfos.os）：'lin' 命中 linux。
	if rows := peerRows(t, cs, "/api/peers?os=lin", hdr); len(rows) != 1 || rows[0]["id"] != "1000002" {
		t.Errorf("os LIKE filter rows = %v", idsOf(rows))
	}
	// device_group_name LIKE：'Alp' 命中 Alpha（用前缀避开 SQLite LIKE
	// 大小写不敏感歧义）。
	if rows := peerRows(t, cs, "/api/peers?device_group_name=Alp", hdr); len(rows) != 1 {
		t.Errorf("device_group_name LIKE filter = %d rows, want 1", len(rows))
	}
	// user_name LIKE。
	if rows := peerRows(t, cs, "/api/peers?user_name=scop", hdr); len(rows) != 1 {
		t.Errorf("user_name LIKE filter = %d rows, want 1", len(rows))
	}
	// is_online=0 → 离线 PeerC。
	rows := peerRows(t, cs, "/api/peers?is_online=0", hdr)
	if len(rows) != 1 || rows[0]["id"] != "1000003" {
		t.Errorf("is_online=0 = %v, want PeerC", idsOf(rows))
	}
	// 分页：pageSize=2 → data 2 行 total 3。
	raw := cs.get(t, "/api/peers?current=1&pageSize=2", hdr, 200)
	m := decodeMap(t, raw)
	if len(m["data"].([]any)) != 2 || m["total"].(float64) != 3 {
		t.Errorf("page1 = %v", m)
	}
	raw = cs.get(t, "/api/peers?current=2&pageSize=2", hdr, 200)
	m = decodeMap(t, raw)
	if len(m["data"].([]any)) != 1 || m["total"].(float64) != 3 {
		t.Errorf("page2 = %v", m)
	}
}

// TestContractDevicesScopedBoundary /devices scope 边界：admin 全量、
// global 档全量（含未分组）、scoped 仅授权组内（排除未分组）；
// DeviceView 形状锁定：PeerView 全键 + userGuid/deviceGroupGuid。
func TestContractDevicesScopedBoundary(t *testing.T) {
	cs, as, seed := newDeviceContractServer(t)

	adminHdr := bearer(m2Token(t, as, seed.Admin))
	rows := peerRows(t, cs, "/api/devices", adminHdr)
	if len(rows) != 3 {
		t.Fatalf("admin devices = %d, want 3", len(rows))
	}
	first := rows[0]
	for _, key := range []string{"userGuid", "deviceGroupGuid"} {
		if _, has := first[key]; !has {
			t.Errorf("DeviceView.%s missing（allOf 双键）", key)
		}
	}
	if first["userGuid"] != *seed.PeerA.UserGuid {
		t.Errorf("userGuid = %v, want %s", first["userGuid"], *seed.PeerA.UserGuid)
	}
	if first["deviceGroupGuid"] != seed.DG1.Guid {
		t.Errorf("deviceGroupGuid = %v, want %s", first["deviceGroupGuid"], seed.DG1.Guid)
	}

	// global 档（devices.view global）：全量含未分组。
	globalHdr := bearer(m2Token(t, as, seed.Global))
	if rows := peerRows(t, cs, "/api/devices", globalHdr); len(rows) != 3 {
		t.Errorf("global scope devices = %d, want 3", len(rows))
	}

	// scoped（DG1）：仅 PeerA，未分组 PeerB 排除。
	scopedHdr := bearer(m2Token(t, as, seed.Scoped))
	rows = peerRows(t, cs, "/api/devices", scopedHdr)
	if len(rows) != 1 || rows[0]["id"] != "1000001" {
		t.Errorf("scoped devices = %v, want only PeerA（未分组排除）", idsOf(rows))
	}
}

// TestContractDevicesFilters 过滤语义差异锁定：device_group_name 在
// /devices 精确匹配（'Alp' 不命中，'Alpha' 命中）；device_name LIKE
// hostname；user_name/os 精确；group_name LIKE 组名。
func TestContractDevicesFilters(t *testing.T) {
	cs, as, seed := newDeviceContractServer(t)
	hdr := bearer(m2Token(t, as, seed.Admin))

	// ★ device_group_name 精确（与 /peers 的 LIKE 相对）。
	if rows := peerRows(t, cs, "/api/devices?device_group_name=Alp", hdr); len(rows) != 0 {
		t.Errorf("exact match must reject 'Alp', got %v", idsOf(rows))
	}
	if rows := peerRows(t, cs, "/api/devices?device_group_name=Alpha", hdr); len(rows) != 1 {
		t.Errorf("exact match 'Alpha' = %d rows, want 1", len(rows))
	}
	// device_name LIKE sysinfos.hostname。
	if rows := peerRows(t, cs, "/api/devices?device_name=alpha", hdr); len(rows) != 1 {
		t.Errorf("device_name LIKE = %d rows, want 1", len(rows))
	}
	// user_name 精确。
	if rows := peerRows(t, cs, "/api/devices?user_name=scoped", hdr); len(rows) != 1 {
		t.Errorf("user_name exact = %d rows, want 1", len(rows))
	}
	if rows := peerRows(t, cs, "/api/devices?user_name=scop", hdr); len(rows) != 0 {
		t.Errorf("user_name exact must reject substring, got %v", idsOf(rows))
	}
	// os 精确。
	if rows := peerRows(t, cs, "/api/devices?os=linux", hdr); len(rows) != 1 {
		t.Errorf("os exact linux = %d rows, want 1", len(rows))
	}
	// group_name LIKE。
	if rows := peerRows(t, cs, "/api/devices?group_name=Bet", hdr); len(rows) != 1 {
		t.Errorf("group_name LIKE = %d rows, want 1", len(rows))
	}
}

// TestContractDeviceStatusUpdate 批量启停：enabled/disabled 双向 +
// 结果形状（succeeded/failed/total/succeededCount/failedCount）。
func TestContractDeviceStatusUpdate(t *testing.T) {
	cs, as, seed := newDeviceContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	raw := cs.patch(t, "/api/devices/status", map[string]any{
		"guids": []string{seed.PeerA.UUID, seed.PeerB.UUID}, "status": "disabled",
	}, admin, 200)
	m := decodeMap(t, raw)
	if m["total"].(float64) != 2 || m["succeededCount"].(float64) != 2 || m["failedCount"].(float64) != 0 {
		t.Errorf("result = %v", m)
	}
	if failed, ok := m["failed"].([]any); !ok || len(failed) != 0 {
		t.Errorf("failed = %v, want []", m["failed"])
	}
	if succ, ok := m["succeeded"].([]any); !ok || len(succ) != 2 {
		t.Errorf("succeeded = %v, want 2 items", m["succeeded"])
	}
	p, _ := repository.NewPeerRepo(as.DB).FindByUUID(context.Background(), seed.PeerA.UUID)
	if p.Status != entity.PeerStatusDisabled {
		t.Errorf("peer status = %d, want 0", p.Status)
	}

	// 恢复 enabled。
	cs.patch(t, "/api/devices/status", map[string]any{
		"guids": []string{seed.PeerA.UUID}, "status": "enabled",
	}, admin, 200)
	p, _ = repository.NewPeerRepo(as.DB).FindByUUID(context.Background(), seed.PeerA.UUID)
	if p.Status != entity.PeerStatusActive {
		t.Errorf("peer status = %d, want 1", p.Status)
	}

	// 空 guids → 400（minItems 1）。
	cs.invalid(t, http.MethodPatch, "/api/devices/status", map[string]any{
		"guids": []string{}, "status": "disabled",
	}, admin, 400)
}

// TestContractDeviceStatusUnauthorized 批量越权 403：任一设备越出
// scope 整体拒绝；未知 uuid 优先（404）。
func TestContractDeviceStatusUnauthorized(t *testing.T) {
	cs, as, seed := newDeviceContractServer(t)
	grantPermission(t, as, seed.RoleDev.Guid, "devices.status") // Scoped 升格为 status 操作者
	scoped := bearer(m2Token(t, as, seed.Scoped))

	// PeerB 未分组（scope 外）→ 整体 403。
	raw := cs.patch(t, "/api/devices/status", map[string]any{
		"guids": []string{seed.PeerB.UUID}, "status": "disabled",
	}, scoped, 403)
	assertMessage(t, raw, "Batch request contains unauthorized devices")

	// 混合批次：未知 uuid 优先于越权判定（404）。
	cs.patch(t, "/api/devices/status", map[string]any{
		"guids": []string{"uuid-ghost", seed.PeerB.UUID}, "status": "disabled",
	}, scoped, 404)
}

// TestContractDeviceUpdate 更新设备：note 任意 edit 操作者可改；
// 关联字段变更需超管；名称不存在 → 400；空串解绑 → null。
func TestContractDeviceUpdate(t *testing.T) {
	cs, as, seed := newDeviceContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	// note 更新（admin 即超管，直接可改）。
	raw := cs.patch(t, "/api/devices/"+seed.PeerA.UUID,
		map[string]any{"note": "ops note"}, admin, 200)
	view := decodeMap(t, raw)
	if view["note"] != "ops note" {
		t.Errorf("note = %v", view["note"])
	}

	// 关联字段：userName 按名解析。
	raw = cs.patch(t, "/api/devices/"+seed.PeerA.UUID,
		map[string]any{"userName": "global"}, admin, 200)
	if m := decodeMap(t, raw); m["userGuid"] != seed.Global.Guid {
		t.Errorf("userGuid = %v, want %s", m["userGuid"], seed.Global.Guid)
	}
	// 空串解绑 → userGuid null。
	raw = cs.patch(t, "/api/devices/"+seed.PeerA.UUID,
		map[string]any{"userName": ""}, admin, 200)
	if m := decodeMap(t, raw); m["userGuid"] != nil {
		t.Errorf("userGuid after unbind = %v, want null", m["userGuid"])
	}
	// 名称不存在 → 400。
	raw = cs.patch(t, "/api/devices/"+seed.PeerA.UUID,
		map[string]any{"deviceGroupName": "Ghost"}, admin, 400)
	assertMessage(t, raw, "Device group not found")

	// 非 super admin 变更关联字段 → 403（roles 路线文案）。
	grantPermission(t, as, seed.RoleDev.Guid, "devices.edit")
	scoped := bearer(m2Token(t, as, seed.Scoped))
	raw = cs.patch(t, "/api/devices/"+seed.PeerA.UUID,
		map[string]any{"userName": "global"}, scoped, 403)
	assertMessage(t, raw, "Super administrator permission required")
}

// TestContractDeviceDelete 删除设备：级联删 active_connections；
// 复删 404。
func TestContractDeviceDelete(t *testing.T) {
	cs, as, seed := newDeviceContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	cs.delete(t, "/api/devices/"+seed.PeerA.UUID, admin, 200)
	ctx := context.Background()
	if _, err := repository.NewPeerRepo(as.DB).FindByUUID(ctx, seed.PeerA.UUID); err != repository.ErrNotFound {
		t.Errorf("peer must be deleted, err = %v", err)
	}
	conns, _ := repository.NewActiveConnectionRepo(as.DB).ListConnIds(ctx, seed.PeerA.UUID)
	if len(conns) != 0 {
		t.Errorf("active_connections must cascade-delete, got %v", conns)
	}
	// 复删 → 404。
	cs.delete(t, "/api/devices/"+seed.PeerA.UUID, admin, 404)
}

// TestContractDeviceDisconnect 断连：scope 内放行、越 scope 403
// （device 路线文案）、未知设备 404、空 connIds = 断开全部活跃连接
// （v0.2.1：非数值审计 conn_id 跳过）、无权限码 403。
func TestContractDeviceDisconnect(t *testing.T) {
	cs, as, seed := newDeviceContractServer(t)
	scoped := bearer(m2Token(t, as, seed.Scoped)) // devices.disconnect @ DG1

	// scope 内（PeerA ∈ DG1）。
	raw := cs.post(t, "/api/devices/"+seed.PeerA.UUID+"/disconnect",
		map[string]any{"connIds": []int{11, 99}}, scoped, 200)
	if m := decodeMap(t, raw); m["pending_disconnect_count"].(float64) != 2 {
		t.Errorf("pending = %v, want 2", m["pending_disconnect_count"])
	}

	// 播一条活跃审计行（数值 conn_id=42）与非数值行（应跳过）。
	uid := seed.PeerA.UUID
	ptr := func(s string) *string { return &s }
	if err := as.DB.Create(&entity.ConnectionAudit{
		DeviceId: seed.PeerA.ID, DeviceUuid: &uid, ConnId: ptr("42"),
		Action: entity.ConnActionEstablished, RequestedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed active conn: %v", err)
	}
	if err := as.DB.Create(&entity.ConnectionAudit{
		DeviceId: seed.PeerA.ID, DeviceUuid: &uid, ConnId: ptr("seed-nx"),
		Action: entity.ConnActionEstablished, RequestedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed non-numeric conn: %v", err)
	}

	// 空 connIds → 200：断开全部活跃连接（仅数值 42 入队 → pending=3）。
	raw = cs.post(t, "/api/devices/"+seed.PeerA.UUID+"/disconnect",
		map[string]any{"connIds": []int{}}, scoped, 200)
	if m := decodeMap(t, raw); m["pending_disconnect_count"].(float64) != 3 {
		t.Errorf("empty connIds pending = %v, want 3", m["pending_disconnect_count"])
	}

	// 缺省（body 无 connIds 键）→ 200 同语义（幂等，仍 3）。
	raw = cs.post(t, "/api/devices/"+seed.PeerA.UUID+"/disconnect",
		map[string]any{}, scoped, 200)
	if m := decodeMap(t, raw); m["pending_disconnect_count"].(float64) != 3 {
		t.Errorf("default body pending = %v, want 3", m["pending_disconnect_count"])
	}

	// 越 scope（PeerC ∈ DG2）。
	raw = cs.post(t, "/api/devices/"+seed.PeerC.UUID+"/disconnect",
		map[string]any{"connIds": []int{1}}, scoped, 403)
	assertMessage(t, raw, "Device is not in an authorized device group")

	// 未知设备 404。
	cs.post(t, "/api/devices/uuid-ghost/disconnect",
		map[string]any{"connIds": []int{1}}, scoped, 404)

	// 只有 devices.view 的用户：路由级 403 Access denied。
	global := bearer(m2Token(t, as, seed.Global))
	raw = cs.post(t, "/api/devices/"+seed.PeerA.UUID+"/disconnect",
		map[string]any{"connIds": []int{11}}, global, 403)
	assertMessage(t, raw, "Access denied")
}

// ---- 本文件辅助 ----

// peerRows GET 列表断言辅助：返回 data 数组（map 形态）。
func peerRows(t *testing.T, cs *contractServer, path string, hdr map[string]string) []map[string]any {
	t.Helper()
	raw := cs.get(t, path, hdr, 200)
	m := decodeMap(t, raw)
	arr, ok := m["data"].([]any)
	if !ok {
		t.Fatalf("%s: data missing: %v", path, m)
	}
	rows := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		rows = append(rows, item.(map[string]any))
	}
	return rows
}

// idsOf 提取行 id 列表（错误信息可读性）。
func idsOf(rows []map[string]any) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r["id"].(string))
	}
	return out
}

// contains 报告列表是否含目标串。
func contains(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

// assertMessage 断言错误包络 message 纯文本。
func assertMessage(t *testing.T, raw []byte, want string) {
	t.Helper()
	var env struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("envelope not json: %v (%s)", err, raw)
	}
	if env.Message != want {
		t.Errorf("message = %q, want %q", env.Message, want)
	}
}
