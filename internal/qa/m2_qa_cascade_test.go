// m2_qa_cascade_test.go 级联与传播独立用例（QA 第 2 轮补强）：
//
//	device-group 删除：组内 peers.deviceGroupGuid 置空（detach 语义）+
//	组行消失 + 幂等 404 + 角色指派引用保护 400
//	strategy unassign：宿主表（peers/device_groups/users）strategyGuid
//	清空 + 未绑定/幽灵目标部分成功语义
//	strategy 删除：三处宿主引用事务性置空（共享知识 9）+ 心跳不再下发
package qa

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// contains 原始响应字节包含子串（raw 为 []byte，包装 strings.Contains）。
func contains(raw []byte, sub string) bool {
	return bytes.Contains(raw, []byte(sub))
}

// TestQADeviceGroupDeleteDetachesPeers 删除设备组：组内设备解绑（置空
// deviceGroupGuid）而非删除；组行消失；重复删除 404；被角色指派引用的
// 组拒绝删除（400 RESTRICT 语义）。
func TestQADeviceGroupDeleteDetachesPeers(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))

	// 引用保护：DG1 被 scoped 的 assignment 关联 → 400。
	status, _, raw := doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/device-groups/"+seed.DG1.Guid, nil, admin)
	if status != http.StatusBadRequest || !contains(raw, "Device group is referenced by role assignments") {
		t.Fatalf("referenced delete = %d %s, want 400 referenced", status, raw)
	}

	// 建组 → 加入 PeerB（body=peer.id[]）→ 删组。
	status, resp, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/device-groups",
		map[string]any{"name": "qa-cascade-group"}, admin)
	if status != http.StatusOK {
		t.Fatalf("create group = %d (%s)", status, raw)
	}
	guid, _ := resp["guid"].(string)
	if guid == "" {
		t.Fatalf("group guid missing: %v", resp)
	}
	status, resp, raw = doJSON(t, client, http.MethodPost,
		as.TS.URL+"/api/device-groups/"+guid,
		[]string{seed.PeerB.ID}, admin)
	if status != http.StatusOK || resp["added_count"] != float64(1) {
		t.Fatalf("add devices = %d %v (%s)", status, resp, raw)
	}
	status, _, raw = doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/device-groups/"+guid, nil, admin)
	if status != http.StatusOK {
		t.Fatalf("delete group = %d (%s)", status, raw)
	}

	// 组行消失；PeerB 仍存在但 deviceGroupGuid 置空（detach 语义记录）。
	var gcount int64
	if err := as.DB.Model(&entity.DeviceGroup{}).Where("guid = ?", guid).Count(&gcount).Error; err != nil || gcount != 0 {
		t.Errorf("group rows = %d (err %v), want 0", gcount, err)
	}
	var p entity.Peer
	if err := as.DB.Where("uuid = ?", seed.PeerB.UUID).First(&p).Error; err != nil {
		t.Fatalf("peer must survive group deletion: %v", err)
	}
	if p.DeviceGroupGuid != nil {
		t.Errorf("peer.deviceGroupGuid = %v, want nil（删除组后置空）", *p.DeviceGroupGuid)
	}

	// 重复删除 → 404 固定文案。
	status, _, raw = doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/device-groups/"+guid, nil, admin)
	if status != http.StatusNotFound || !contains(raw, "Device group does not exist") {
		t.Errorf("repeat delete = %d %s, want 404", status, raw)
	}
}

// TestQAStrategyUnassignClearsHostReferences unassign 解绑：宿主表
// strategyGuid 置 NULL；未绑定目标/幽灵目标记入 errors（部分成功语义，
// HTTP 恒 200）。
func TestQAStrategyUnassignClearsHostReferences(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))
	sguid := seed.StrategyS.Guid
	assignURL := as.TS.URL + "/api/strategies/" + sguid + "/assign"
	unassignURL := as.TS.URL + "/api/strategies/" + sguid + "/unassign"

	// 绑定三形态：设备组 DG2 / 设备 PeerB / 用户 Global。
	status, resp, raw := doJSON(t, client, http.MethodPost, assignURL,
		map[string]any{"target_type": "device_group", "target_guids": []string{seed.DG2.Guid}}, admin)
	if status != http.StatusOK || len(resp["success"].([]any)) != 1 {
		t.Fatalf("assign group = %d %v (%s)", status, resp, raw)
	}
	status, resp, raw = doJSON(t, client, http.MethodPost, assignURL,
		map[string]any{"target_type": "device", "target_guids": []string{seed.PeerB.UUID}}, admin)
	if status != http.StatusOK || len(resp["success"].([]any)) != 1 {
		t.Fatalf("assign device = %d %v (%s)", status, resp, raw)
	}
	status, resp, raw = doJSON(t, client, http.MethodPost, assignURL,
		map[string]any{"target_type": "user", "target_guids": []string{seed.Global.Guid}}, admin)
	if status != http.StatusOK || len(resp["success"].([]any)) != 1 {
		t.Fatalf("assign user = %d %v (%s)", status, resp, raw)
	}
	assertHostStrategy(t, as, "device_groups", seed.DG2.Guid, sguid)
	assertHostStrategy(t, as, "peers", seed.PeerB.UUID, sguid)
	assertHostStrategy(t, as, "users", seed.Global.Guid, sguid)

	// unassign（target_guids 契约去重，重复项不产生逐项错误）：
	// 第一发解绑 DG2 → success；第二发同目标 → not bound；幽灵组 → not found。
	status, resp, raw = doJSON(t, client, http.MethodPost, unassignURL,
		map[string]any{"target_type": "device_group", "target_guids": []string{seed.DG2.Guid}}, admin)
	if status != http.StatusOK || len(resp["success"].([]any)) != 1 {
		t.Fatalf("unassign first = %d %v (%s)", status, resp, raw)
	}
	assertHostStrategy(t, as, "device_groups", seed.DG2.Guid, "")
	status, resp, raw = doJSON(t, client, http.MethodPost, unassignURL,
		map[string]any{"target_type": "device_group",
			"target_guids": []string{seed.DG2.Guid, "qa-ghost-group"}}, admin)
	if status != http.StatusOK {
		t.Fatalf("unassign second = %d (%s)", status, raw)
	}
	success, _ := resp["success"].([]any)
	errs, _ := resp["errors"].([]any)
	if len(success) != 0 || len(errs) != 2 {
		t.Fatalf("unassign result = success:%v errors:%v, want 0 success + 2 errors", success, errs)
	}
	reasons := map[string]bool{}
	for _, e := range errs {
		m, _ := e.(map[string]any)
		reasons[m["reason"].(string)] = true
	}
	if !reasons["Device group is not bound to this strategy"] || !reasons["Device group not found"] {
		t.Errorf("unassign reasons = %v, want not-bound + not-found", reasons)
	}

	// 设备/用户解绑后宿主清空。
	status, resp, raw = doJSON(t, client, http.MethodPost, unassignURL,
		map[string]any{"target_type": "device", "target_guids": []string{seed.PeerB.UUID}}, admin)
	if status != http.StatusOK || len(resp["success"].([]any)) != 1 {
		t.Fatalf("unassign device = %d %v (%s)", status, resp, raw)
	}
	status, resp, raw = doJSON(t, client, http.MethodPost, unassignURL,
		map[string]any{"target_type": "user", "target_guids": []string{seed.Global.Guid}}, admin)
	if status != http.StatusOK || len(resp["success"].([]any)) != 1 {
		t.Fatalf("unassign user = %d %v (%s)", status, resp, raw)
	}
	assertHostStrategy(t, as, "peers", seed.PeerB.UUID, "")
	assertHostStrategy(t, as, "users", seed.Global.Guid, "")
}

// TestQAStrategyDeleteDetachesAllHosts 删除策略：peers/users/device_
// groups 三处 strategyGuid 事务性置空（共享知识 9），策略行消失，
// 设备心跳不再收到该策略下发。
func TestQAStrategyDeleteDetachesAllHosts(t *testing.T) {
	as, seed := m2Server(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))
	sguid := seed.StrategyS.Guid

	// 追加 users 引用（SeedM2 已有 PeerA 直挂 + DG1 引用）。
	if err := as.DB.Model(&entity.User{}).Where("guid = ?", seed.Global.Guid).
		Update("strategyGuid", sguid).Error; err != nil {
		t.Fatalf("bind user strategy: %v", err)
	}

	status, _, raw := doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/strategies/"+sguid, nil, admin)
	if status != http.StatusOK {
		t.Fatalf("delete strategy = %d (%s)", status, raw)
	}

	assertHostStrategy(t, as, "peers", seed.PeerA.UUID, "")
	assertHostStrategy(t, as, "device_groups", seed.DG1.Guid, "")
	assertHostStrategy(t, as, "users", seed.Global.Guid, "")
	var scount int64
	if err := as.DB.Model(&entity.Strategy{}).Where("guid = ?", sguid).Count(&scount).Error; err != nil || scount != 0 {
		t.Errorf("strategy rows = %d, want 0", scount)
	}

	// 重复删除 → 404 固定文案。
	status, _, raw = doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/strategies/"+sguid, nil, admin)
	if status != http.StatusNotFound || !contains(raw, "Strategy not found") {
		t.Errorf("repeat delete = %d %s, want 404 Strategy not found", status, raw)
	}

	// 传播闭环：引用已清，心跳不再下发策略（modified_at 远早于删除时刻）。
	status, resp, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/heartbeat",
		map[string]any{"id": seed.PeerA.ID, "uuid": seed.PeerA.UUID, "ver": 1, "modified_at": 1}, nil)
	if status != http.StatusOK || len(resp) != 0 {
		t.Errorf("heartbeat after strategy delete = %d %v (%s), want 200 {}", status, resp, raw)
	}
}

// assertHostStrategy 断言宿主表行的 strategyGuid（want 空串 = NULL）。
func assertHostStrategy(t *testing.T, as *apptest.AppServer, table, key, want string) {
	t.Helper()
	var got *string
	switch table {
	case "peers":
		var p entity.Peer
		if err := as.DB.Where("uuid = ?", key).First(&p).Error; err != nil {
			t.Fatalf("load peer %s: %v", key, err)
		}
		got = p.StrategyGuid
	case "users":
		var u entity.User
		if err := as.DB.Where("guid = ?", key).First(&u).Error; err != nil {
			t.Fatalf("load user %s: %v", key, err)
		}
		got = u.StrategyGuid
	case "device_groups":
		var g entity.DeviceGroup
		if err := as.DB.Where("guid = ?", key).First(&g).Error; err != nil {
			t.Fatalf("load group %s: %v", key, err)
		}
		got = g.StrategyGuid
	}
	if want == "" {
		if got != nil {
			t.Errorf("%s[%s].strategyGuid = %s, want NULL", table, key, *got)
		}
		return
	}
	if got == nil || *got != want {
		t.Errorf("%s[%s].strategyGuid = %v, want %s", table, key, got, want)
	}
}
