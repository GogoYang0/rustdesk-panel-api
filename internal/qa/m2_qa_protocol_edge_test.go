// m2_qa_protocol_edge_test.go 设备协议边界与限流优先级独立用例
// （QA 第 2 轮补强，避开 m2_device_protocol_test.go 已有断言路径）：
//
//	首跳自动注册后的第二次心跳更新路径（ver/modified_at/lastHeartbeat 落库）
//	conns 非空→空→回连的 active_connections diff 语义与回连恢复
//	策略传播第二跳（策略内容更新后重新下发）+ 悬空引用三级回退
//	sysinfo 不自动注册红线（DB 断言）+ 字段覆盖语义 + preset 关联/兜底
//	设备限流 tracker=id 优先级细粒度验证 + 429 包络形状
//	M1 per-IP per-route 限流在 M2 后仍生效（管理端点抽验）
package qa

import (
	"net/http"
	"testing"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// TestQAHeartbeatSecondHopUpdatePath 未知 uuid 首跳自动注册后，第二次
// 心跳必须走更新路径：peers 仍单行且 id/ver/modifiedAt/lastHeartbeat
// 全部更新（Upsert OnConflict DoUpdates 语义）。
func TestQAHeartbeatSecondHopUpdatePath(t *testing.T) {
	as, _ := m2Server(t)
	firstAt := time.Now().Add(-2 * time.Second)

	status, _, raw := doJSON(t, as.TS.Client(), http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": "555001", "uuid": "uuid-qa-second", "ver": 1001000,
			"modified_at": firstAt.UnixMilli(), "conns": []int{}}, nil)
	if status != http.StatusOK {
		t.Fatalf("first hop status = %d (%s)", status, raw)
	}

	secondAt := time.Now()
	status, resp, raw := doJSON(t, as.TS.Client(), http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": "555001", "uuid": "uuid-qa-second", "ver": 1002000,
			"modified_at": secondAt.UnixMilli()}, nil)
	if status != http.StatusOK || len(resp) != 0 {
		t.Fatalf("second hop = %d %v (%s), want 200 {}", status, resp, raw)
	}

	var count int64
	if err := as.DB.Model(&entity.Peer{}).Where("uuid = ?", "uuid-qa-second").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("peers rows = %d (err %v), want 1", count, err)
	}
	var p entity.Peer
	if err := as.DB.Where("uuid = ?", "uuid-qa-second").First(&p).Error; err != nil {
		t.Fatalf("load peer: %v", err)
	}
	if p.ID != "555001" || p.Ver != 1002000 || p.ModifiedAt != secondAt.UnixMilli() {
		t.Errorf("second hop not applied: id=%s ver=%d modifiedAt=%d, want 555001/1002000/%d",
			p.ID, p.Ver, p.ModifiedAt, secondAt.UnixMilli())
	}
	if p.LastHeartbeat == nil || p.LastHeartbeat.Before(secondAt.Add(-5*time.Second)) {
		t.Errorf("lastHeartbeat = %v, want refreshed at second hop", p.LastHeartbeat)
	}
	// 注册路径 status 走 DB 默认 1（ACTIVE）。
	if p.Status != entity.PeerStatusActive {
		t.Errorf("status = %d, want %d (DB default)", p.Status, entity.PeerStatusActive)
	}
}

// TestQAHeartbeatConnsDrainThenReconnect conns 数据面 diff：非空→空
// 触发断连（active_connections 清空），再回连恢复（重新同步快照）。
func TestQAHeartbeatConnsDrainThenReconnect(t *testing.T) {
	as, _ := m2Server(t)
	url := as.TS.URL + "/api/heartbeat"
	client := as.TS.Client()
	base := map[string]any{"id": "555002", "uuid": "uuid-qa-conns", "ver": 1, "modified_at": time.Now().UnixMilli()}

	// 首跳携带 conns [21,22] → 两行。
	status, resp, raw := doJSON(t, client, http.MethodPost, url, withConns(base, 21, 22), nil)
	if status != http.StatusOK || len(resp) != 0 {
		t.Fatalf("first hop = %d %v (%s)", status, resp, raw)
	}
	if n := countConns(t, as, "uuid-qa-conns"); n != 2 {
		t.Fatalf("conns after first hop = %d, want 2", n)
	}

	// 非空→空：全部断开，active_connections 清空，响应仍 {}。
	status, resp, raw = doJSON(t, client, http.MethodPost, url, withConns(base), nil)
	if status != http.StatusOK || len(resp) != 0 {
		t.Fatalf("drain hop = %d %v (%s)", status, resp, raw)
	}
	if n := countConns(t, as, "uuid-qa-conns"); n != 0 {
		t.Fatalf("conns after drain = %d, want 0", n)
	}

	// 回连 [21,22,23]：diff 恢复三行。
	status, resp, raw = doJSON(t, client, http.MethodPost, url, withConns(base, 21, 22, 23), nil)
	if status != http.StatusOK || len(resp) != 0 {
		t.Fatalf("reconnect hop = %d %v (%s)", status, resp, raw)
	}
	if n := countConns(t, as, "uuid-qa-conns"); n != 3 {
		t.Fatalf("conns after reconnect = %d, want 3", n)
	}

	// 部分断开 [23]：仅保留 23（diff 同步非增量插入）。
	_, _, _ = doJSON(t, client, http.MethodPost, url, withConns(base, 23), nil)
	if n := countConns(t, as, "uuid-qa-conns"); n != 1 {
		t.Fatalf("conns after partial = %d, want 1", n)
	}
}

// TestQAStrategyGateReDeliveryAfterUpdate 策略传播第二跳：应用后不再
// 下发；策略内容变更（UpdatedAt 前移）后同设备重新下发新配置。
func TestQAStrategyGateReDeliveryAfterUpdate(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))
	gate := seed.StrategyS.UpdatedAt.UnixMilli()

	// 应用到门槛（modified_at = gate）→ 不下发。
	status, resp, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": seed.PeerA.ID, "uuid": seed.PeerA.UUID, "ver": 1, "modified_at": gate}, nil)
	if status != http.StatusOK || len(resp) != 0 {
		t.Fatalf("at gate = %d %v (%s), want 200 {}", status, resp, raw)
	}

	// 管理侧更新策略内容（UpdatedAt 刷新；name 为必填字段）。
	status, _, raw = doJSON(t, client, http.MethodPatch,
		as.TS.URL+"/api/strategies/"+seed.StrategyS.Guid,
		map[string]any{"name": seed.StrategyS.Name,
			"config_options": map[string]string{"allow_log_anonymous": "false"}}, admin)
	if status != http.StatusOK {
		t.Fatalf("strategy update = %d (%s)", status, raw)
	}

	// 设备仍报旧 modified_at → 重新下发（updatedAt 严格大于 modified_at）。
	status, resp, raw = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": seed.PeerA.ID, "uuid": seed.PeerA.UUID, "ver": 1, "modified_at": gate}, nil)
	if status != http.StatusOK {
		t.Fatalf("re-delivery heartbeat = %d (%s)", status, raw)
	}
	strat, _ := resp["strategy"].(map[string]any)
	if strat == nil {
		t.Fatalf("strategy must be re-delivered after update: %v", resp)
	}
	opts, _ := strat["config_options"].(map[string]any)
	if opts["allow_log_anonymous"] != "false" {
		t.Errorf("config_options = %v, want updated allow_log_anonymous=false", opts)
	}
	if ma, _ := resp["modified_at"].(float64); int64(ma) <= gate {
		t.Errorf("modified_at = %v, want > %d", resp["modified_at"], gate)
	}
}

// TestQAStrategyScopedUserFallbackChain 三级回退可达路径（设计 §1.1④）：
// ① 设备直挂策略优先于 ②归属用户策略；设备无直挂时回退用户策略；
// 设备/用户均无直挂时回退 ③设备组策略（peers FK 约束使悬空 guid 不可
// 落库，悬空分支为纯防御，不在此构造）。
func TestQAStrategyScopedUserFallbackChain(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()

	// SeedM2 的 S fixture 内容为布尔值形态（脏数据，解析防御为空对象），
	// 本用例改写为契约合法的 Record<string,string> 后断言内容。
	// 注意 SeedM2 里 PeerA 直挂 S、归属用户 scoped 与 DG1 无关本用例。
	if err := as.DB.Model(&entity.Strategy{}).Where("guid = ?", seed.StrategyS.Guid).
		Update("configOptions", `{"allow_log_anonymous":"true"}`).Error; err != nil {
		t.Fatalf("normalize s config: %v", err)
	}

	// S2（字符串值合法形态）挂到归属用户 scoped 与设备组 DG2。
	s2 := &entity.Strategy{Guid: "qa-strategy-s2", Name: "qa-s2",
		ConfigOptions: `{"allow_tcp_tunnel":"true"}`,
		CreatedAt:     seed.Now, UpdatedAt: seed.Now}
	if err := as.DB.Create(s2).Error; err != nil {
		t.Fatalf("seed s2: %v", err)
	}
	if err := as.DB.Model(&entity.User{}).Where("guid = ?", seed.Scoped.Guid).
		Update("strategyGuid", s2.Guid).Error; err != nil {
		t.Fatalf("set user strategy: %v", err)
	}
	if err := as.DB.Model(&entity.DeviceGroup{}).Where("guid = ?", seed.DG2.Guid).
		Update("strategyGuid", s2.Guid).Error; err != nil {
		t.Fatalf("set group strategy: %v", err)
	}

	beat := func(uuid, id string) map[string]any {
		t.Helper()
		status, resp, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
			map[string]any{"id": id, "uuid": uuid, "ver": 1, "modified_at": 1}, nil)
		if status != http.StatusOK {
			t.Fatalf("heartbeat %s = %d (%s)", uuid, status, raw)
		}
		return resp
	}
	configOf := func(resp map[string]any) map[string]any {
		t.Helper()
		strat, _ := resp["strategy"].(map[string]any)
		if strat == nil {
			return nil
		}
		opts, _ := strat["config_options"].(map[string]any)
		return opts
	}

	// ① > ②：PeerA 直挂 S（allow_log_anonymous），归属用户挂 S2
	// → 直挂策略优先。
	if opts := configOf(beat(seed.PeerA.UUID, seed.PeerA.ID)); opts == nil || opts["allow_log_anonymous"] != "true" {
		t.Errorf("device-level strategy must win: %v", opts)
	}

	// ②：PeerB（global 名下，无直挂、无组）→ 用户级回退。global 用户
	// 无策略，先把 S2 转挂 global 验证；scoped 用户不再参与该设备。
	if err := as.DB.Model(&entity.User{}).Where("guid = ?", seed.Scoped.Guid).
		Update("strategyGuid", nil).Error; err != nil {
		t.Fatalf("clear scoped strategy: %v", err)
	}
	if err := as.DB.Model(&entity.User{}).Where("guid = ?", seed.Global.Guid).
		Update("strategyGuid", s2.Guid).Error; err != nil {
		t.Fatalf("set global strategy: %v", err)
	}
	if opts := configOf(beat(seed.PeerB.UUID, seed.PeerB.ID)); opts == nil || opts["allow_tcp_tunnel"] != "true" {
		t.Errorf("user-level fallback must deliver s2: %v", opts)
	}

	// ③：PeerC（owner 名下 @ DG2，owner 无策略）→ 设备组级回退。
	if opts := configOf(beat(seed.PeerC.UUID, seed.PeerC.ID)); opts == nil || opts["allow_tcp_tunnel"] != "true" {
		t.Errorf("group-level fallback must deliver s2: %v", opts)
	}
}

// TestQASysinfoNoAutoRegisterAndFieldSemantics sysinfo 红线与字段语义：
// 未知 uuid 不建 peer/sysinfo 行（不自动注册）；已注册设备核心字段
// "提供即覆盖"、preset 列"非空真值才覆盖"、preset-note 兜底不覆盖、
// preset-device-group-name 关联（组不存在跳过不报错）。
func TestQASysinfoNoAutoRegisterAndFieldSemantics(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	url := as.TS.URL + "/api/sysinfo"

	// 未知 uuid：恒 200 ID_NOT_FOUND，且不建任何行。
	status, _, raw := doJSON(t, client, http.MethodPost, url,
		map[string]any{"uuid": "uuid-qa-ghost", "hostname": "evil"}, nil)
	if status != http.StatusOK || !contains(raw, "ID_NOT_FOUND") {
		t.Fatalf("unknown uuid = %d %s, want 200 ID_NOT_FOUND", status, raw)
	}
	for _, tbl := range []string{"peers", "sysinfos"} {
		var n int64
		if err := as.DB.Table(tbl).Where("uuid = ?", "uuid-qa-ghost").Count(&n).Error; err != nil || n != 0 {
			t.Errorf("%s rows for unknown uuid = %d (err %v), want 0（不自动注册）", tbl, n, err)
		}
	}

	// 已注册设备首报：核心字段写入 + preset-device-group-name 关联 DG1
	// + preset-note 兜底（peers.note 原为空）。
	status, _, raw = doJSON(t, client, http.MethodPost, url, map[string]any{
		"uuid": seed.PeerB.UUID, "hostname": "qa-host", "os": "linux",
		"cpu": "riscv", "memory": "4GB",
		"preset-username":          "pu1",
		"preset-device-group-name": seed.DG1.Name,
		"preset-note":              "first note",
		"preset-address-book-name": "ignored-m3",
	}, nil)
	if status != http.StatusOK || !contains(raw, "SYSINFO_UPDATED") {
		t.Fatalf("registered uuid = %d %s, want 200 SYSINFO_UPDATED", status, raw)
	}
	var si entity.Sysinfo
	if err := as.DB.Where("uuid = ?", seed.PeerB.UUID).First(&si).Error; err != nil {
		t.Fatalf("load sysinfo: %v", err)
	}
	if si.Hostname != "qa-host" || si.OS != "linux" || si.CPU != "riscv" || si.Memory != "4GB" {
		t.Errorf("core fields = %+v", si)
	}
	if si.PresetUsername != "pu1" {
		t.Errorf("preset_username = %q, want pu1", si.PresetUsername)
	}
	var p entity.Peer
	if err := as.DB.Where("uuid = ?", seed.PeerB.UUID).First(&p).Error; err != nil {
		t.Fatalf("load peer: %v", err)
	}
	if p.DeviceGroupGuid == nil || *p.DeviceGroupGuid != seed.DG1.Guid {
		t.Errorf("deviceGroupGuid = %v, want %s（preset 组关联）", p.DeviceGroupGuid, seed.DG1.Guid)
	}
	if p.Note != "first note" {
		t.Errorf("note = %q, want 兜底 first note", p.Note)
	}

	// 二报：核心字段提供即覆盖；preset 空串保留存量；preset-note 不覆盖
	// 已有注记；幽灵组名跳过关联但响应仍 SYSINFO_UPDATED。
	status, _, raw = doJSON(t, client, http.MethodPost, url, map[string]any{
		"uuid": seed.PeerB.UUID, "hostname": "qa-host-2",
		"preset-device-group-name": "no-such-group",
		"preset-note":              "second note",
	}, nil)
	if status != http.StatusOK || !contains(raw, "SYSINFO_UPDATED") {
		t.Fatalf("second report = %d %s", status, raw)
	}
	if err := as.DB.Where("uuid = ?", seed.PeerB.UUID).First(&si).Error; err != nil {
		t.Fatalf("reload sysinfo: %v", err)
	}
	if si.Hostname != "qa-host-2" {
		t.Errorf("hostname = %q, want qa-host-2（提供即覆盖）", si.Hostname)
	}
	if si.OS != "linux" || si.CPU != "riscv" {
		t.Errorf("omitted fields must persist: os=%q cpu=%q", si.OS, si.CPU)
	}
	if si.PresetUsername != "pu1" {
		t.Errorf("preset_username = %q, want pu1（非空真值才覆盖→空串保留）", si.PresetUsername)
	}
	if err := as.DB.Where("uuid = ?", seed.PeerB.UUID).First(&p).Error; err != nil {
		t.Fatalf("reload peer: %v", err)
	}
	if p.Note != "first note" {
		t.Errorf("note = %q, want first note（已有注记不被 preset-note 覆盖）", p.Note)
	}
	if p.DeviceGroupGuid == nil || *p.DeviceGroupGuid != seed.DG1.Guid {
		t.Errorf("deviceGroupGuid = %v, want unchanged（幽灵组名跳过）", p.DeviceGroupGuid)
	}
}

// TestQADeviceRateLimitTrackerPriority 设备限流 tracker 优先级与包络：
// 同 id 异 uuid 共桶（id 优先于 uuid）、异 id 异桶、heartbeat/sysinfo
// 路由键隔离、429 包络三形态。
func TestQADeviceRateLimitTrackerPriority(t *testing.T) {
	as := newQAServer(t) // 限流开启
	client := as.TS.Client()
	url := as.TS.URL + "/api/heartbeat"

	beat := func(id, uuid string) int {
		status, _, _ := doJSON(t, client, http.MethodPost, url,
			map[string]any{"id": id, "uuid": uuid, "ver": 1, "modified_at": 1}, nil)
		return status
	}

	for i := 0; i < 10; i++ {
		if c := beat("qa-id-1", "uuid-qa-rl-a"); c != http.StatusOK {
			t.Fatalf("beat[%d] = %d, want 200", i, c)
		}
	}
	// 桶打满后：同 id 换 uuid → 仍 429（tracker 取 id，与 uuid 无关）。
	if c := beat("qa-id-1", "uuid-qa-rl-b"); c != http.StatusTooManyRequests {
		t.Errorf("same id new uuid = %d, want 429（id 优先于 uuid）", c)
	}
	// 不同 id（uuid 同/异均可）→ 独立桶放行。
	if c := beat("qa-id-2", "uuid-qa-rl-a"); c != http.StatusOK {
		t.Errorf("new id same uuid = %d, want 200（设备维度隔离）", c)
	}
	if c := beat("qa-id-3", "uuid-qa-rl-c"); c != http.StatusOK {
		t.Errorf("new id new uuid = %d, want 200", c)
	}

	// heartbeat 满，同 tracker sysinfo 不受影响（method+route 独立桶）。
	for i := 0; i < 5; i++ {
		status, _, _ := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/sysinfo",
			map[string]any{"uuid": "uuid-qa-rl-a"}, nil)
		if status != http.StatusOK {
			t.Fatalf("sysinfo[%d] = %d, want 200", i, status)
		}
	}
	status, parsed, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/sysinfo",
		map[string]any{"uuid": "uuid-qa-rl-a"}, nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("6th sysinfo = %d (%s), want 429", status, raw)
	}
	assertEnvelope(t, status, parsed, http.StatusTooManyRequests, "ThrottlerException: Too many requests")

	// 缺 id 缺 uuid → 回退 IP 桶：同 IP 第 3 类仍独立（此处仅验证形状，
	// IP 桶已被上两轮请求消耗部分配额，允许 200/429 双态但必须非 5xx）。
	status, _, _ = doJSON(t, client, http.MethodPost, url,
		map[string]any{"ver": 1, "modified_at": 1}, nil)
	if status >= 500 {
		t.Errorf("fallback tracker status = %d, want < 500", status)
	}
}

// TestQAManagementEndpointM1RateLimitStillEnforced M1 per-IP per-route
// 限流在 M2 后仍生效：/api/users/me/password 5/min——限流层先于 JWT，
// 无 token 6 连发前 5 次 401、第 6 次 429；相邻路由 login 独立桶不受
// 牵连（per-route 隔离回归抽验）。
func TestQAManagementEndpointM1RateLimitStillEnforced(t *testing.T) {
	as := newQAServer(t)
	client := as.TS.Client()
	url := as.TS.URL + "/api/users/me/password"

	for i := 0; i < 5; i++ {
		status, _, _ := doJSON(t, client, http.MethodPatch, url,
			map[string]any{"old_password": "x", "new_password": "y"}, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("call[%d] = %d, want 401（JWT 先于业务，限流未触发）", i, status)
		}
	}
	status, parsed, raw := doJSON(t, client, http.MethodPatch, url,
		map[string]any{"old_password": "x", "new_password": "y"}, nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("6th call = %d (%s), want 429", status, raw)
	}
	assertEnvelope(t, status, parsed, http.StatusTooManyRequests, "ThrottlerException: Too many requests")

	// per-route 隔离：login 独立桶，错误密码 401 而非 429。
	status, _, raw = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/login",
		map[string]any{"username": "nobody", "password": "wrong"}, nil)
	if status != http.StatusUnauthorized {
		t.Errorf("login after password route exhausted = %d (%s), want 401（路由桶隔离）", status, raw)
	}
}

// withConns 返回带/不带 conns 的心跳体（复制避免用例间串改）。
func withConns(base map[string]any, connIDs ...int64) map[string]any {
	out := make(map[string]any, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	if connIDs != nil {
		out["conns"] = connIDs
	} else {
		out["conns"] = []int64{}
	}
	return out
}

// countConns 统计设备活跃连接行数。
func countConns(t *testing.T, as *apptest.AppServer, uuid string) int64 {
	t.Helper()
	var n int64
	if err := as.DB.Model(&entity.ActiveConnection{}).Where("deviceUuid = ?", uuid).Count(&n).Error; err != nil {
		t.Fatalf("count conns: %v", err)
	}
	return n
}
