// m2_device_protocol_test.go 设备端协议与设备域独立安全/兼容用例
// （设计 §2 qa/m2_device_protocol_test.go）：未知字段 400、并发首跳唯一键
// 安全、modified_at 门槛、断连回路、ID_NOT_FOUND text/plain、设备维度限流、
// 越 scope 断连 403（含 denied 审计落库）、批量越权 403、被禁用户 401。
//
// 与 contract 包的分工：contract 锁 openapi 请求/响应形状；本包聚焦
// 服务端行为语义与安全反例，不做契约校验（独立再验一遍核心语义）。
package qa

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// m2Server 禁限流全栈服务器 + M2 fixture。
func m2Server(t *testing.T) (*apptest.AppServer, *testutil.SeedM2Data) {
	t.Helper()
	as := newQAServerNoLimit(t)
	return as, testutil.SeedM2(t, as.DB)
}

// seedToken 为种子用户签发 token（种子用户无口令，无法走 /api/login；
// 签发与登录共用 TokenService.Generate 路径）。
func seedToken(t *testing.T, as *apptest.AppServer, user *entity.User) string {
	t.Helper()
	svc := authsvc.NewTokenService(repository.NewUserTokenRepo(as.DB), as.Config.JWTSecret, 1)
	tok, err := svc.Generate(context.Background(), user, dto.LoginDevice{
		Id: "qa", Uuid: "qa-uuid", Name: "qa", Os: "linux", Type: "web",
	})
	if err != nil {
		t.Fatalf("seedToken: %v", err)
	}
	return tok
}

// grantQA 为角色补授权限码（构造 devices.status 等 scoped 操作者）。
func grantQA(t *testing.T, as *apptest.AppServer, roleGuid, code string) {
	t.Helper()
	if err := as.DB.Create(&entity.RolePermission{RoleGuid: roleGuid, PermissionCode: code}).Error; err != nil {
		t.Fatalf("grantQA %s: %v", code, err)
	}
}

// TestM2DeviceProtocolUnknownFieldRejected 未知字段 400（两协议端点）。
func TestM2DeviceProtocolUnknownFieldRejected(t *testing.T) {
	as, _ := m2Server(t)
	client := as.TS.Client()

	status, _, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": "1", "uuid": "u", "ver": 1, "modified_at": 1, "evil": "x"}, nil)
	if status != http.StatusBadRequest {
		t.Errorf("heartbeat unknown field status = %d, want 400 (%s)", status, raw)
	}
	status, _, raw = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/sysinfo",
		map[string]any{"uuid": "u", "evil": "x"}, nil)
	if status != http.StatusBadRequest {
		t.Errorf("sysinfo unknown field status = %d, want 400 (%s)", status, raw)
	}
}

// TestM2HeartbeatConcurrentFirstHop 并发首跳唯一键安全：N 并发同一
// 新 uuid 全部 200，peers 仅一行（Upsert OnConflict 语义）。
func TestM2HeartbeatConcurrentFirstHop(t *testing.T) {
	as, _ := m2Server(t)
	client := as.TS.Client()

	const n = 16
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _, _ = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
				map[string]any{"id": "888001", "uuid": "uuid-race", "ver": 1, "modified_at": 1}, nil)
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("heartbeat[%d] status = %d, want 200", i, c)
		}
	}
	var count int64
	if err := as.DB.Model(&entity.Peer{}).Where("uuid = ?", "uuid-race").Count(&count).Error; err != nil {
		t.Fatalf("count peers: %v", err)
	}
	if count != 1 {
		t.Errorf("peers rows = %d, want 1", count)
	}
}

// TestM2HeartbeatModifiedAtGate 门槛机制：updatedAt(ms) > modified_at
// 才下发；应用后（新 modified_at 上报）不再重复下发——assign 传播闭环。
func TestM2HeartbeatModifiedAtGate(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	gate := seed.StrategyS.UpdatedAt.UnixMilli()

	// 早于门槛 → strategy.config_options + modified_at。
	status, resp, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": seed.PeerA.ID, "uuid": seed.PeerA.UUID, "ver": 1, "modified_at": gate - 1}, nil)
	if status != 200 {
		t.Fatalf("heartbeat status = %d (%s)", status, raw)
	}
	if _, ok := resp["strategy"]; !ok {
		t.Fatalf("strategy must be delivered below gate: %v", resp)
	}
	if resp["modified_at"].(float64) != float64(gate) {
		t.Errorf("modified_at = %v, want %d", resp["modified_at"], gate)
	}

	// 以新 modified_at 上报 → {}（不重复下发）。
	status, resp, raw = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": seed.PeerA.ID, "uuid": seed.PeerA.UUID, "ver": 1, "modified_at": gate}, nil)
	if status != 200 || len(resp) != 0 {
		t.Errorf("heartbeat at/above gate = %d %v, want 200 {}（严格大于门槛）(%s)", status, resp, raw)
	}
}

// TestM2DisconnectRoundTrip 断连回路（服务端语义）：入队 → 心跳下发 →
// 停止上报确认出队。
func TestM2DisconnectRoundTrip(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))

	// 入队。
	status, resp, raw := doJSON(t, client, http.MethodPost,
		as.TS.URL+"/api/devices/"+seed.PeerA.UUID+"/disconnect",
		map[string]any{"connIds": []int{11, 12}}, admin)
	if status != 200 || resp["pending_disconnect_count"].(float64) != 2 {
		t.Fatalf("disconnect enqueue = %d %v (%s)", status, resp, raw)
	}

	// 心跳仍上报 → disconnect 键。
	status, resp, raw = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": seed.PeerA.ID, "uuid": seed.PeerA.UUID, "ver": 1,
			"modified_at": time.Now().UnixMilli(), "conns": []int{11, 12}}, nil)
	if status != 200 {
		t.Fatalf("heartbeat status = %d (%s)", status, raw)
	}
	if fmt.Sprint(resp["disconnect"]) != fmt.Sprint([]any{float64(11), float64(12)}) {
		t.Errorf("disconnect = %v, want [11 12]", resp["disconnect"])
	}

	// 11 不再上报 → 出队；pending 只剩 12。
	_, resp, _ = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": seed.PeerA.ID, "uuid": seed.PeerA.UUID, "ver": 1,
			"modified_at": time.Now().UnixMilli(), "conns": []int{12}}, nil)
	if fmt.Sprint(resp["disconnect"]) != fmt.Sprint([]any{float64(12)}) {
		t.Errorf("disconnect after confirm = %v, want [12]", resp["disconnect"])
	}

	// 12 也不再上报 → 队列清空，响应 {}。
	_, resp, _ = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": seed.PeerA.ID, "uuid": seed.PeerA.UUID, "ver": 1,
			"modified_at": time.Now().UnixMilli(), "conns": []int{}}, nil)
	if len(resp) != 0 {
		t.Errorf("pending must drain: %v", resp)
	}
}

// TestM2SysinfoIDNotFoundPlainText 未注册设备：text/plain 恒 200
// ID_NOT_FOUND（Content-Type 与 enum 文案双断言）。
func TestM2SysinfoIDNotFoundPlainText(t *testing.T) {
	as, _ := m2Server(t)
	client := as.TS.Client()

	req, err := http.NewRequest(http.MethodPost, as.TS.URL+"/api/sysinfo",
		strings.NewReader(`{"uuid":"uuid-none"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("sysinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("content-type = %q, want text/plain", resp.Header.Get("Content-Type"))
	}
	if body != "ID_NOT_FOUND" {
		t.Errorf("body = %q, want ID_NOT_FOUND", body)
	}
}

// TestM2DeviceRateLimit 设备维度限流：同 tracker 超 heartbeat 10/min
// → 429；换 uuid 新桶放行；sysinfo 独立配额 5/min。
func TestM2DeviceRateLimit(t *testing.T) {
	as := newQAServer(t) // 限流开启
	client := as.TS.Client()

	for i := 0; i < 10; i++ {
		status, _, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
			map[string]any{"id": "777001", "uuid": "uuid-rl-a", "ver": 1, "modified_at": 1}, nil)
		if status != 200 {
			t.Fatalf("heartbeat[%d] = %d, want 200 (%s)", i, status, raw)
		}
	}
	status, _, _ := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": "777001", "uuid": "uuid-rl-a", "ver": 1, "modified_at": 1}, nil)
	if status != http.StatusTooManyRequests {
		t.Errorf("11th heartbeat = %d, want 429", status)
	}

	// 换 uuid → 独立桶。
	status, _, _ = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": "777002", "uuid": "uuid-rl-b", "ver": 1, "modified_at": 1}, nil)
	if status != 200 {
		t.Errorf("other tracker = %d, want 200（设备维度隔离）", status)
	}

	// sysinfo 5/min 独立配额。
	for i := 0; i < 5; i++ {
		doJSON(t, client, http.MethodPost, as.TS.URL+"/api/sysinfo",
			map[string]any{"uuid": "uuid-rl-a"}, nil)
	}
	status, _, _ = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/sysinfo",
		map[string]any{"uuid": "uuid-rl-a"}, nil)
	if status != http.StatusTooManyRequests {
		t.Errorf("6th sysinfo = %d, want 429", status)
	}
}

// TestM2ScopedOperatorForbidden 越 scope 断连 403 + denied 审计落库
// （targetType=device，固定文案）。
func TestM2ScopedOperatorForbidden(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped)) // devices.disconnect @ DG1

	status, _, raw := doJSON(t, client, http.MethodPost,
		as.TS.URL+"/api/devices/"+seed.PeerC.UUID+"/disconnect",
		map[string]any{"connIds": []int{1}}, scoped)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", status, raw)
	}
	if !strings.Contains(string(raw), "Device is not in an authorized device group") {
		t.Errorf("message = %s", raw)
	}

	// denied 审计落库（红线：拒绝决策写 console_audits）。
	var audits []entity.ConsoleAudit
	if err := as.DB.Where("actorUserGuid = ? AND result = ?",
		seed.Scoped.Guid, "denied").Find(&audits).Error; err != nil {
		t.Fatalf("query audits: %v", err)
	}
	if len(audits) == 0 {
		t.Fatal("denied audit must be recorded")
	}
	found := false
	for _, a := range audits {
		if a.TargetGuid == seed.PeerC.UUID && a.Action == "devices.disconnect" {
			found = true
		}
	}
	if !found {
		t.Errorf("audit rows = %+v, want devices.disconnect @ PeerC", audits)
	}
}

// TestM2BatchUnauthorizedDevices403 批量越权 403：任一设备越出 scope
// 整体拒绝，已授权设备不部分生效。
func TestM2BatchUnauthorizedDevices403(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	grantQA(t, as, seed.RoleDev.Guid, "devices.status")
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	status, _, raw := doJSON(t, client, http.MethodPatch, as.TS.URL+"/api/devices/status",
		map[string]any{"guids": []string{seed.PeerA.UUID, seed.PeerB.UUID}, "status": "disabled"}, scoped)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", status, raw)
	}
	if !strings.Contains(string(raw), "Batch request contains unauthorized devices") {
		t.Errorf("message = %s", raw)
	}
	// 整体拒绝：scope 内的 PeerA 也不生效。
	var count int64
	if err := as.DB.Model(&entity.Peer{}).
		Where("uuid = ? AND status = ?", seed.PeerA.UUID, entity.PeerStatusDisabled).
		Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("batch must be atomic on 403, PeerA disabled rows = %d", count)
	}
}

// TestM2DisabledUser401 被禁用户访问受保护设备端点 → 401 固定文案
// （Auth+状态复核路线；JWT 本身有效，拒绝来自实时查库）。
func TestM2DisabledUser401(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	disabled := authHeader(seedToken(t, as, seed.Disabled))

	status, _, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/peers", nil, disabled)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (%s)", status, raw)
	}
	if !strings.Contains(string(raw), "Account does not exist or has been disabled") {
		t.Errorf("message = %s", raw)
	}
}
