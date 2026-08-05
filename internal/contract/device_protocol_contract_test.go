// device_protocol_contract_test.go 设备端协议契约用例（M2 退出标准 ★）：
// heartbeat/sysinfo 以 openapi.yaml 为准绳做请求/响应双向校验
// （kin-openapi openapi3filter），快照锁定首跳自动注册、conns diff、
// 断连回路、策略下发门槛（严格大于）、preset 关联规则与未知字段 400。
package contract

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/server"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// newDeviceProtocolServer 全栈契约服务器：真实路由 + 内存库 + SeedM2。
// 禁 per-IP 限流避免用例互相挤兑（设备维度限流由 qa 专项覆盖）。
func newDeviceProtocolServer(t *testing.T) (*contractServer, *apptest.AppServer, *testutil.SeedM2Data) {
	t.Helper()
	as := apptest.NewAppServer(t, nil)
	seed := testutil.SeedM2(t, as.DB)
	cs := newContractServerWith(t, func() *server.Router {
		return server.NewRouter(server.RouterDeps{
			Logger:           testutil.TestLogger(),
			RateLimitEnabled: false,
			DB:               as.DB,
			Config:           as.Config,
		})
	})
	return cs, as, seed
}

// m2Token 以 TokenService 为种子用户直接签发 token（种子用户无口令
// 无法走 /api/login；签发与登录共用 TokenService.Generate 路径）。
func m2Token(t *testing.T, as *apptest.AppServer, user *entity.User) string {
	t.Helper()
	svc := authsvc.NewTokenService(repository.NewUserTokenRepo(as.DB), as.Config.JWTSecret, 1)
	tok, err := svc.Generate(context.Background(), user, dto.LoginDevice{
		Id: "contract", Uuid: "contract-uuid", Name: "contract", Os: "linux", Type: "web",
	})
	if err != nil {
		t.Fatalf("m2Token: generate failed: %v", err)
	}
	return tok
}

// heartbeatBody 构造心跳报文（conns 可省略 = 键缺失语义）。
func heartbeatBody(id, uuid string, ver, modifiedAt int64, conns []int) map[string]any {
	body := map[string]any{"id": id, "uuid": uuid, "ver": ver, "modified_at": modifiedAt}
	if conns != nil {
		body["conns"] = conns
	}
	return body
}

// decodeMap 解析响应 JSON 为 map。
func decodeMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("response not json object: %v (%s)", err, raw)
	}
	return m
}

// nums 断言 JSON 数字数组（float64 形态）与期望 int 列表一致。
func nums(t *testing.T, v any, want ...int64) {
	t.Helper()
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("expected array, got %T (%v)", v, v)
	}
	if len(arr) != len(want) {
		t.Fatalf("array = %v, want %v", arr, want)
	}
	for i, item := range arr {
		f, ok := item.(float64)
		if !ok || int64(f) != want[i] {
			t.Fatalf("array[%d] = %v, want %d", i, item, want[i])
		}
	}
}

// ---- heartbeat ----

// TestContractHeartbeatFirstHop 首跳自动注册：响应 {}（条件键均未命中），
// peers 行落库（status 走 DB 默认 1=active）。
func TestContractHeartbeatFirstHop(t *testing.T) {
	cs, as, _ := newDeviceProtocolServer(t)
	raw := cs.post(t, "/api/heartbeat", heartbeatBody("9000001", "uuid-first-hop", 1001000, 1000, nil), nil, 200)
	m := decodeMap(t, raw)
	if len(m) != 0 {
		t.Errorf("first hop response = %v, want empty object", m)
	}
	p, err := repository.NewPeerRepo(as.DB).FindByUUID(context.Background(), "uuid-first-hop")
	if err != nil {
		t.Fatalf("peer not registered: %v", err)
	}
	if p.ID != "9000001" || p.Ver != 1001000 || p.ModifiedAt != 1000 || p.Status != entity.PeerStatusActive {
		t.Errorf("registered peer = %+v", p)
	}
	if p.LastHeartbeat == nil {
		t.Error("lastHeartbeat must be set on first hop")
	}
}

// TestContractHeartbeatConnsDiff conns 快照 diff 同步：[1,2] → [2,3] →
// 键缺失（不动快照）。
func TestContractHeartbeatConnsDiff(t *testing.T) {
	cs, as, _ := newDeviceProtocolServer(t)
	cs.post(t, "/api/heartbeat", heartbeatBody("9000002", "uuid-conns", 1, 1, []int{1, 2}), nil, 200)
	cs.post(t, "/api/heartbeat", heartbeatBody("9000002", "uuid-conns", 1, 2, []int{2, 3}), nil, 200)

	conns, err := repository.NewActiveConnectionRepo(as.DB).ListConnIds(context.Background(), "uuid-conns")
	if err != nil {
		t.Fatalf("list conns: %v", err)
	}
	got := map[int64]bool{}
	for _, c := range conns {
		got[c] = true
	}
	if !got[2] || !got[3] || got[1] || len(got) != 2 {
		t.Errorf("conns after diff = %v, want {2,3}", conns)
	}

	// conns 键缺失：快照保持不变（指针 nil ≠ 空数组）。
	cs.post(t, "/api/heartbeat", heartbeatBody("9000002", "uuid-conns", 1, 3, nil), nil, 200)
	conns, _ = repository.NewActiveConnectionRepo(as.DB).ListConnIds(context.Background(), "uuid-conns")
	if len(conns) != 2 {
		t.Errorf("conns after omitted key = %v, want unchanged {2,3}", conns)
	}
}

// TestContractHeartbeatDisconnectLoop 断连回路（§4.1）：管理端入队 →
// 心跳收到 disconnect → 客户端停止上报 → pending 消失。全链走真实 API。
func TestContractHeartbeatDisconnectLoop(t *testing.T) {
	cs, as, seed := newDeviceProtocolServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	// 入队 11、12。
	raw := cs.post(t, "/api/devices/"+seed.PeerA.UUID+"/disconnect",
		map[string]any{"connIds": []int{11, 12}}, admin, 200)
	if m := decodeMap(t, raw); m["pending_disconnect_count"].(float64) != 2 {
		t.Errorf("pending count = %v, want 2", m["pending_disconnect_count"])
	}

	// 心跳仍上报 11、12 → disconnect 键出现（客户端待断开）。
	raw = cs.post(t, "/api/heartbeat",
		heartbeatBody(seed.PeerA.ID, seed.PeerA.UUID, 1, time.Now().UnixMilli(), []int{11, 12}), nil, 200)
	m := decodeMap(t, raw)
	nums(t, m["disconnect"], 11, 12)
	if _, has := m["strategy"]; has {
		t.Errorf("strategy must be absent (modified_at is newer than strategy updatedAt): %v", m)
	}

	// 客户端已断开 11（不再上报）→ 11 出队，pending 只剩 12。
	raw = cs.post(t, "/api/heartbeat",
		heartbeatBody(seed.PeerA.ID, seed.PeerA.UUID, 1, time.Now().UnixMilli(), []int{12}), nil, 200)
	nums(t, decodeMap(t, raw)["disconnect"], 12)

	// 客户端断开 12（上报空数组）→ pending 清空，响应回到 {}。
	raw = cs.post(t, "/api/heartbeat",
		heartbeatBody(seed.PeerA.ID, seed.PeerA.UUID, 1, time.Now().UnixMilli(), []int{}), nil, 200)
	if m := decodeMap(t, raw); len(m) != 0 {
		t.Errorf("response = %v, want empty object（断连回路闭合）", m)
	}
}

// TestContractHeartbeatStrategyGate 策略下发门槛（严格大于）：
// modified_at 早于策略 updatedAt → 下发 config_options + 新 modified_at；
// 相等 → 不下发。
func TestContractHeartbeatStrategyGate(t *testing.T) {
	cs, as, seed := newDeviceProtocolServer(t)

	// 自建策略：config_options 恒 string 值（锁 openapi
	// additionalProperties:string 契约）；updatedAt 截断到整秒保证
	// 毫秒值经 DB 往返稳定。
	gate := time.Now().Truncate(time.Second)
	strat := &entity.Strategy{
		Guid: "contract-strategy", Name: "gate-strategy",
		ConfigOptions: `{"access_ip":"10.0.0.9","custom-rustdesk-port":"21116"}`,
		CreatedAt:     gate, UpdatedAt: gate,
	}
	if err := as.DB.Create(strat).Error; err != nil {
		t.Fatalf("create strategy: %v", err)
	}
	if err := as.DB.Model(&entity.Peer{}).
		Where("uuid = ?", seed.PeerA.UUID).
		Update("strategyGuid", strat.Guid).Error; err != nil {
		t.Fatalf("bind strategy to peer: %v", err)
	}

	// 早于门槛 → 下发。
	raw := cs.post(t, "/api/heartbeat",
		heartbeatBody(seed.PeerA.ID, seed.PeerA.UUID, 1, gate.UnixMilli()-1, nil), nil, 200)
	m := decodeMap(t, raw)
	strategy, ok := m["strategy"].(map[string]any)
	if !ok {
		t.Fatalf("strategy key missing: %v", m)
	}
	opts, ok := strategy["config_options"].(map[string]any)
	if !ok || opts["access_ip"] != "10.0.0.9" {
		t.Errorf("config_options = %v, want access_ip=10.0.0.9", strategy["config_options"])
	}
	if m["modified_at"].(float64) != float64(gate.UnixMilli()) {
		t.Errorf("modified_at = %v, want %d（策略 updatedAt 毫秒）", m["modified_at"], gate.UnixMilli())
	}

	// 等于门槛（严格大于才下发）→ {}。
	raw = cs.post(t, "/api/heartbeat",
		heartbeatBody(seed.PeerA.ID, seed.PeerA.UUID, 1, gate.UnixMilli(), nil), nil, 200)
	if m := decodeMap(t, raw); len(m) != 0 {
		t.Errorf("response at gate boundary = %v, want empty object", m)
	}
}

// TestContractHeartbeatUnknownField400 未知字段 400
// （forbidNonWhitelisted 语义，双防线：契约校验器拒绝 + 服务 400 包络）。
func TestContractHeartbeatUnknownField400(t *testing.T) {
	cs, _, _ := newDeviceProtocolServer(t)
	cs.invalid(t, http.MethodPost, "/api/heartbeat", map[string]any{
		"id": "9000009", "uuid": "uuid-evil", "ver": 1, "modified_at": 1, "evil": "x",
	}, nil, 400)
}

// TestContractHeartbeatMissingRequired400 缺必需字段 → 400 包络。
func TestContractHeartbeatMissingRequired400(t *testing.T) {
	cs, _, _ := newDeviceProtocolServer(t)
	cs.invalid(t, http.MethodPost, "/api/heartbeat", map[string]any{"id": "9000002"}, nil, 400)
}

// ---- sysinfo ----

// TestContractSysinfoIDNotFound 未注册设备：恒 200 text/plain ID_NOT_FOUND
// （不自动注册，红线）。
func TestContractSysinfoIDNotFound(t *testing.T) {
	cs, as, _ := newDeviceProtocolServer(t)
	raw := cs.post(t, "/api/sysinfo", map[string]any{"uuid": "uuid-not-registered"}, nil, 200)
	if strings.TrimSpace(string(raw)) != "ID_NOT_FOUND" {
		t.Errorf("body = %q, want ID_NOT_FOUND", raw)
	}
	// 未注册不落 peers 行。
	_, err := repository.NewPeerRepo(as.DB).FindByUUID(context.Background(), "uuid-not-registered")
	if err != repository.ErrNotFound {
		t.Errorf("peer must not auto-register, err = %v", err)
	}
}

// TestContractSysinfoUpdated 核心字段"提供即覆盖"：已注册设备 upsert，
// 未提供字段保留存量。
func TestContractSysinfoUpdated(t *testing.T) {
	cs, as, seed := newDeviceProtocolServer(t)
	raw := cs.post(t, "/api/sysinfo", map[string]any{
		"uuid": seed.PeerA.UUID, "hostname": "alpha-new", "os": "windows 11 pro", "cpu": "m1",
	}, nil, 200)
	if strings.TrimSpace(string(raw)) != "SYSINFO_UPDATED" {
		t.Errorf("body = %q, want SYSINFO_UPDATED", raw)
	}
	si, err := repository.NewSysinfoRepo(as.DB).FindByUUID(context.Background(), seed.PeerA.UUID)
	if err != nil {
		t.Fatalf("sysinfo missing: %v", err)
	}
	if si.Hostname != "alpha-new" || si.OS != "windows 11 pro" || si.CPU != "m1" {
		t.Errorf("provided fields = %s/%s/%s, want alpha-new/windows 11 pro/m1", si.Hostname, si.OS, si.CPU)
	}
	if si.Username != "alpha-user" || si.Memory != "16GB" {
		t.Errorf("unprovided fields must keep existing: username=%q memory=%q", si.Username, si.Memory)
	}
}

// TestContractSysinfoCreateForKnownPeer 已注册但无 sysinfo 行 → 创建。
func TestContractSysinfoCreateForKnownPeer(t *testing.T) {
	cs, as, seed := newDeviceProtocolServer(t) // PeerC 无 sysinfo 行
	cs.post(t, "/api/sysinfo", map[string]any{
		"uuid": seed.PeerC.UUID, "hostname": "gamma-host", "os": "macos",
	}, nil, 200)
	si, err := repository.NewSysinfoRepo(as.DB).FindByUUID(context.Background(), seed.PeerC.UUID)
	if err != nil {
		t.Fatalf("sysinfo not created: %v", err)
	}
	if si.Hostname != "gamma-host" || si.OS != "macos" {
		t.Errorf("created sysinfo = %+v", si)
	}
}

// TestContractSysinfoPresetRules preset 规则：组关联回写、note 兜底
// （不覆盖已有）、preset_username 落库、未知组名跳过、二次 note 不覆盖。
func TestContractSysinfoPresetRules(t *testing.T) {
	cs, as, seed := newDeviceProtocolServer(t)
	ctx := context.Background()

	cs.post(t, "/api/sysinfo", map[string]any{
		"uuid":                     seed.PeerB.UUID,
		"preset-device-group-name": "Beta",
		"preset-note":              "from preset",
		"preset-username":          "preset-admin",
	}, nil, 200)

	p, err := repository.NewPeerRepo(as.DB).FindByUUID(ctx, seed.PeerB.UUID)
	if err != nil {
		t.Fatalf("peer missing: %v", err)
	}
	if p.DeviceGroupGuid == nil || *p.DeviceGroupGuid != seed.DG2.Guid {
		t.Errorf("deviceGroupGuid = %v, want %s（按名关联）", p.DeviceGroupGuid, seed.DG2.Guid)
	}
	if p.Note != "from preset" {
		t.Errorf("note = %q, want 兜底写入", p.Note)
	}
	si, err := repository.NewSysinfoRepo(as.DB).FindByUUID(ctx, seed.PeerB.UUID)
	if err != nil {
		t.Fatalf("sysinfo missing: %v", err)
	}
	if si.PresetUsername != "preset-admin" {
		t.Errorf("preset_username = %q, want preset-admin", si.PresetUsername)
	}

	// 未知组名：跳过不报错，组关联不变。
	cs.post(t, "/api/sysinfo", map[string]any{
		"uuid": seed.PeerB.UUID, "preset-device-group-name": "Ghost",
	}, nil, 200)
	p, _ = repository.NewPeerRepo(as.DB).FindByUUID(ctx, seed.PeerB.UUID)
	if p.DeviceGroupGuid == nil || *p.DeviceGroupGuid != seed.DG2.Guid {
		t.Errorf("unknown group must be skipped, deviceGroupGuid = %v", p.DeviceGroupGuid)
	}

	// note 已非空 → preset-note 不再覆盖。
	cs.post(t, "/api/sysinfo", map[string]any{
		"uuid": seed.PeerB.UUID, "preset-note": "second",
	}, nil, 200)
	p, _ = repository.NewPeerRepo(as.DB).FindByUUID(ctx, seed.PeerB.UUID)
	if p.Note != "from preset" {
		t.Errorf("note = %q, want 不覆盖已有注记", p.Note)
	}
}

// TestContractSysinfoUnknownField400 未知字段 400（含 kebab 键白名单外）。
func TestContractSysinfoUnknownField400(t *testing.T) {
	cs, _, _ := newDeviceProtocolServer(t)
	cs.invalid(t, http.MethodPost, "/api/sysinfo",
		map[string]any{"uuid": "uuid-x", "evil-key": "1"}, nil, 400)
}

// TestContractSysinfoMissingUUID400 缺 uuid → 400。
func TestContractSysinfoMissingUUID400(t *testing.T) {
	cs, _, _ := newDeviceProtocolServer(t)
	cs.invalid(t, http.MethodPost, "/api/sysinfo", map[string]any{"hostname": "h"}, nil, 400)
}
